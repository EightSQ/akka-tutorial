package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.systems.MasterSystem;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		this.wantedHashes = new HashSet<>();
		this.wantedHashesVersion = -1;
		this.workType = WorkType.NO_WORK;
		this.hashesPerSecond = 0;
		this.requestedWork = false;
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class WelcomeMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private ActorRef localMaster;
	}

	@Data @NoArgsConstructor
	public static class WorkShiftMessage implements Serializable {
		private static final long serialVersionUID = -349283922748609598L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HintWorkMessage implements Serializable {
		private static final long serialVersionUID = 1129302748609598L;
		private String alphabet;
		private long nextPermutation;
		private long areaLength;
		private int wantedHashesVersion;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class CrackWorkMessage implements Serializable {
		private static final long serialVersionUID = 2812990118248609598L;
		private String alphabet;
		private long passwordLength;
		private byte[] passwordHash;
		private long nextCombination;
		private long areaLength;
	}

	@Data @NoArgsConstructor
	public static class WorkThiefMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
	}

	@Data @AllArgsConstructor @NoArgsConstructor
	public static class RequestHashSetMessage implements Serializable {
		private static final long serialVersionUID = 2039203942748609598L;
		private int wantedHashesVersion;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HashSetDistributionMessage implements Serializable {
		private static final long serialVersionUID = 2039203942748609598L;
		HashSet<byte[]> hashes;
		private int wantedHashesVersion;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
	private final ActorRef largeMessageProxy;
	private long registrationTime;
	private ActorRef localMaster;
	private ActorRef globalMaster;

	public enum WorkType {
		NO_WORK, HINT, PASSWORD
	}

	private Boolean requestedWork;

	// Both Passwords and Hints
	private WorkType workType;
	private String alphabet;
	private long areaLength;
	private long hashesPerSecond;

	// Only Hints
	private long nextPermutation;
	private HashSet<ByteBuffer> wantedHashes;
	private int wantedHashesVersion;
	private String permutationState;

	// Only Passwords
	private long nextCombination;
	private ByteBuffer passwordHash;
	private long passwordLength;
	private CombinationWrapper combinationState;

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
		
		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(WelcomeMessage.class, this::handle)
				.match(WorkShiftMessage.class, this::handle)
				.match(HintWorkMessage.class, this::handle)
				.match(CrackWorkMessage.class, this::handle)
				.match(WorkThiefMessage.class, this::handle)
				.match(RequestHashSetMessage.class, this::handle)
				.match(HashSetDistributionMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(CurrentClusterState message) {
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) {
		this.register(message.member());
	}

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;
			
			this.getContext()
				.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
				.tell(new Master.RegistrationMessage(), this.self());
			
			this.registrationTime = System.currentTimeMillis();
		}
	}
	
	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}
	
	private void handle(WelcomeMessage message) {
		final long transmissionTime = System.currentTimeMillis() - this.registrationTime;
		this.localMaster = message.getLocalMaster();
		this.globalMaster = this.getSender();
	}

	private void handle(HintWorkMessage message) {
	    this.requestedWork = false;
		log("Received HintWorkMessage with alphabet " + message.getAlphabet() +  " and areaLength " + message.getAreaLength() + " from " + this.sender().path().toString());
		this.workType = WorkType.HINT;
		this.alphabet = message.getAlphabet();
		this.areaLength = message.getAreaLength();
		this.nextPermutation = message.getNextPermutation();

		this.intializeHintState();

		if (this.wantedHashesVersion != message.wantedHashesVersion) {
			log("Requesting hash set from local master.");
			this.localMaster.tell(new RequestHashSetMessage(message.wantedHashesVersion), this.self());
		} else {
			this.self().tell(new WorkShiftMessage(), this.self());
		}
	}

	private void handle(RequestHashSetMessage message) {
		// TODO: Use LargeMessageProxy here if going over another actor system
		//log("Received RequestHashSetMessage!");

		if (this.wantedHashesVersion == message.wantedHashesVersion) {
			HashSet<byte[]> serializableSet = new HashSet<>();
			for (ByteBuffer b : this.wantedHashes) {
				serializableSet.add(b.array());
			}
			this.sender().tell(new HashSetDistributionMessage(serializableSet, message.wantedHashesVersion), this.self());
		} else {
			this.context().system().scheduler().scheduleOnce(
				Duration.ofMillis(100), this.self(), message, this.context().system().dispatcher(), this.sender()
			);
		}
	}

	private void handle(HashSetDistributionMessage message) {
		//log("Received HashSetDistributionMessage from " + this.getSender().path().toString());
		HashSet<ByteBuffer> byteBufferSet = new HashSet<>();
		for (byte[] b : message.getHashes()) {
			byteBufferSet.add(ByteBuffer.wrap(b));
		}

		this.wantedHashes = byteBufferSet;
		this.wantedHashesVersion = message.getWantedHashesVersion();

		this.self().tell(new WorkShiftMessage(), this.self());
	}

	private void handle(CrackWorkMessage message) {
		this.requestedWork = false;
		if (this.areaLength >= 0) {
			log("This is too much work! I have still work to do! areaLength" + this.areaLength + " " + this.workType.toString());
		}

		this.workType = WorkType.PASSWORD;
		this.alphabet = message.getAlphabet();
		this.passwordLength = message.getPasswordLength();
		this.passwordHash = ByteBuffer.wrap(message.getPasswordHash());
		this.nextCombination = message.getNextCombination();
		this.areaLength = message.getAreaLength();

		this.intializePasswordState();

		this.self().tell(new WorkShiftMessage(), this.self());
	}




	private void intializeHintState() {
		//log("Calculating " + this.nextPermutation + "th Permutation of " + this.alphabet);
		this.permutationState = PermuteString.getPermutation(this.alphabet, this.nextPermutation);
		//log("Calculated " + this.nextPermutation + "th Permutation of " + this.alphabet + " = " + this.permutationState);
	}

	private void intializePasswordState() {
		//log("Calculating " + this.nextCombination + "th Combintaion of " + this.alphabet + " of length " + this.passwordLength);
		this.combinationState = new CombinationWrapper(this.alphabet, this.nextCombination, this.passwordLength);
		//log("Calculating " + this.nextCombination + "th Combintaion of " + this.alphabet + " of length " + this.passwordLength + "= " + this.combinationState.toString());

		/* CombinationWrapper wrap = new CombinationWrapper(this.alphabet, 0, this.passwordLength);
		for (int i = 0; i <= this.alphabet.length(); i++) {
			log("combination " + i + ": " + wrap.toString());
			wrap.nextCombination();
		} */

	}

	private void workStep() {
		if (this.workType == WorkType.HINT) {
			// hash the current state
			String hash = betterHash(this.permutationState.substring(1));
			try {
				ByteBuffer hashBuf = ByteBuffer.wrap(Hex.decodeHex(hash));
				if (this.wantedHashes.contains(hashBuf)) { // We discovered a hint
					this.globalMaster.tell(new Master.HintFoundMessage(hashBuf.array(), this.permutationState.charAt(0)), this.getSelf());
				}
			} catch (DecoderException e) {
				log("Failed to parse hash: " + hash);
				e.printStackTrace();
			}
			this.permutationState = PermuteString.nextPermutation(this.permutationState);
			this.nextPermutation++;
			this.areaLength--;
		} else if (this.workType == WorkType.PASSWORD) {
			//log("Starting password work, remaining areaLength: " + areaLength + ", next combination: " + this.combinationState.toString());
			String hash = betterHash(this.combinationState.toString());
			try {
				ByteBuffer hashBuf = ByteBuffer.wrap(Hex.decodeHex(hash));
				if (hashBuf.equals(this.passwordHash)) { // We discovered a hint
					log("I cracked a password and send it to the master!");
					this.globalMaster.tell(new Master.PasswordFoundMessage(this.passwordHash.array(), this.combinationState.toString()), this.getSelf());
					this.areaLength = -1;
					return;
				}
			} catch (DecoderException e) {
				log("Failed to parse hash: " + hash);
				e.printStackTrace();
			}
			this.areaLength--;
//			if (this.areaLength <= -1) {
//				log("Reached end of password range without finding anything..." + this.passwordHash.toString() + " " + this.passwordLength + " " + this.alphabet);
//			}
			this.combinationState.nextCombination();
			this.nextCombination++;
		}
	}

	private static final long workShiftLength = 3000;
	private void handle(WorkShiftMessage message) {
		long shiftStart = System.currentTimeMillis();
		//log("Starting shift, remaining areaLength: " + areaLength);

		switch (this.workType) {
			case HINT:
				this.globalMaster.tell(new Master.NowWorkingOnMessage(new Master.HintWorkPackage(this.nextPermutation, this.areaLength, this.alphabet, this.wantedHashesVersion), this.hashesPerSecond), this.self());
				break;
			case PASSWORD:
				this.globalMaster.tell(new Master.NowWorkingOnMessage(new Master.PasswordWorkPackage(this.nextCombination, this.areaLength, this.alphabet, this.passwordHash.array(), this.passwordLength), this.hashesPerSecond), this.self());
				break;
			case NO_WORK:
			    if (!this.requestedWork) {
					this.globalMaster.tell(new Master.RequestWorkMessage(), this.self());
					this.requestedWork = true;
				}
				return;
		}

		long areaLengthBeforeShift = this.areaLength;
		while (System.currentTimeMillis() - shiftStart <= workShiftLength && areaLength >= 0) {
			this.workStep();
		}
		this.hashesPerSecond = (areaLengthBeforeShift - areaLength) / (1000 * workShiftLength);
		if (areaLength == -1) {
			if (this.workType == WorkType.HINT) {
				this.globalMaster.tell(new Master.NowWorkingOnMessage(new Master.HintWorkPackage(this.nextPermutation, 0, this.alphabet, this.wantedHashesVersion), this.hashesPerSecond), this.self());
			} else {
				//log("Telling Master that we are done with the password work package.");
				this.globalMaster.tell(new Master.NowWorkingOnMessage(new Master.PasswordWorkPackage(this.nextCombination, 0, this.alphabet, this.passwordHash.array(), this.passwordLength), hashesPerSecond), this.self());
			}
			this.workType = WorkType.NO_WORK;
		}

		this.self().tell(new WorkShiftMessage(), this.self());
	}

	public static final long MINIMUM_WORK_SPLITTABLE = 50000; // TODO: Relative Heuristic for work stealing

	private void handle(WorkThiefMessage message) {
		if (this.areaLength > 1) {
			long stolenArea = areaLength / 2;
			this.areaLength -= stolenArea;

			switch (this.workType) {
				case HINT:
					long stolenNextPermutation = nextPermutation + this.areaLength;
					log("Some work of " + stolenArea + " is stolen from me from " + this.sender().path().toString() + ". My remaining area is " + this.areaLength);
					this.sender().tell(new HintWorkMessage(this.alphabet, stolenNextPermutation, stolenArea, this.wantedHashesVersion), this.self());
					break;
				case PASSWORD:
					long stolenNextCombination = nextCombination + this.areaLength;
					this.sender().tell(new CrackWorkMessage(this.alphabet, this.passwordLength, this.passwordHash.array(), stolenNextCombination, stolenArea), this.self());
					break;
			}

		} else {
			this.globalMaster.tell(new Master.RequestWorkMessage(), this.sender());
		}

	}

	private String betterHash(String characters) {
		return DigestUtils.sha256Hex(characters);
	}

	// TODO: Change to better hashing function
	private String hash(String characters) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			// MessageDigest digest = DigestUtils.getSha256Digest(); // apache variant
			byte[] hashedBytes = digest.digest(String.valueOf(characters).getBytes("UTF-8"));
			
			StringBuffer stringBuffer = new StringBuffer();
			for (int i = 0; i < hashedBytes.length; i++) {
				stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			return stringBuffer.toString();
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private void log(String message) {
		System.out.println("[" + this.getSelf().path().toString() + "] " + message);
	}
	
	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, int n, List<String> l) {
		// If size is 1, store the obtained permutation
		if (size == 1)
			l.add(new String(a));

		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, n, l);

			// If size is odd, swap first and last element
			if (size % 2 == 1) {
				char temp = a[0];
				a[0] = a[size - 1];
				a[size - 1] = temp;
			}

			// If size is even, swap i-th and last element
			else {
				char temp = a[i];
				a[i] = a[size - 1];
				a[size - 1] = temp;
			}
		}
	}
}

class CombinationWrapper {
	private String alphabet;
	int base;
	private Map<Character, Integer> charToAlphabetIdx;
	int[] rep;
	public CombinationWrapper(String alphabet, long combinationIdx, long length) {
		Set<Character> chars = new TreeSet<>();
		for( char c : alphabet.toCharArray() ) {
			chars.add(c);
		}

		StringBuilder str = new StringBuilder();
		for (char c : chars) {
			str.append(c);
		}

		this.alphabet = str.toString();
		this.base = this.alphabet.length();
		this.charToAlphabetIdx = new HashMap<>();
		for (int i = 0; i < alphabet.length(); i++) {
			charToAlphabetIdx.put(alphabet.charAt(i), i);
		}
		rep = new int[(int) length];

		for (int i = rep.length - 1; i >= 0; i--) {
			rep[i] = (int) (combinationIdx % this.base);
			combinationIdx -= rep[i];
			combinationIdx /= this.base;
		}
	}

	void nextCombination() {
		for (int i = rep.length - 1; i >= 0; i--) {
			rep[i]++;
			if (rep[i] - base == 0) {
				rep[i] = 0;
				continue;
			}
			break;
		}
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		for (int i : rep) {
			str.append(this.alphabet.charAt(i));
		}
		return str.toString();
	}
}

// Java program to print
// n-th permutation

class PermuteString {

	static String nextPermutation(String str) {
		char[] array = str.toCharArray();

		int i = array.length - 1;
		while (i > 0 && array[i - 1] >= array[i])
			i--;
		if (i <= 0) return "andreaspolze";
		//	return false;

		// Find successor to pivot
		int j = array.length - 1;
		while (array[j] <= array[i - 1])
			j--;
		char temp = array[i - 1];
		array[i - 1] = array[j];
		array[j] = temp;

		// Reverse suffix
		j = array.length - 1;
		while (i < j) {
			temp = array[i];
			array[i] = array[j];
			array[j] = temp;
			i++;
			j--;
		}

		return String.valueOf(array);
	}
	static long[] getFactoradic(long n, int len) {
		long[] factoradic = new long[len];
		long i = 1;
		while (n != 0) {
			factoradic[(int) (len - i)] = n % i;
			n = n / i;
			i++;
		}
		return factoradic;
	}
	// function takes a String,str and Factoradic representation of a number n.
	// returns the nth lexicographic permutaion of character array, str.
	static String getPermutation(String stri, long n) {
		char[] str = stri.toCharArray();
		long[] factoradic = getFactoradic(n, str.length);
		Arrays.sort(str);
		ArrayList<Character> res = new ArrayList<Character>();
		StringBuilder sb = new StringBuilder();
		long pos;
		char c;
		String perm = "";
		boolean[] used = new boolean[str.length]; // by default values are initialised to false.
		for (long i = 0; i < factoradic.length; i++) {
			pos = factoradic[(int) i];
			c = getUnusedCharAtPos(str, pos, used);
			res.add(c);
		}
		for (char some_c : res) {
			sb.append(some_c);
		}
		return (sb.toString());
	}
	//function to get the yet unused character at a given position in a character array.
	private static char getUnusedCharAtPos(char[] str, long pos, boolean[] used) {
		long count = -1;
		for (int i = 0; i < str.length; i++) {
			if (!used[i]) {
				count++;
				if (count == pos) {
					used[i] = true;
					return str[i];
				}
			}
		}
		return ' ';
	}


}