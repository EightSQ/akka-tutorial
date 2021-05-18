package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;

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
		this.wantedHashes = null;
		this.workType = WorkType.NO_WORK;
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class WelcomeMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private ActorRef localMaster;
	}

	@Data
	@NoArgsConstructor
	public static class WorkShiftMessage implements Serializable {
		private static final long serialVersionUID = -349283922748609598L;
	}

	@Data
	@AllArgsConstructor
	public static class HintWorkMessage implements Serializable {
		private static final long serialVersionUID = 1129302748609598L;
		private String alphabet;
		private long nextPermutation;
		private long areaLength;
	}

	@Data
	@AllArgsConstructor
	public static class CrackWorkMessage implements Serializable {
		private static final long serialVersionUID = 2812990118248609598L;
		private String alphabet;
		private long passwordLength;
		private ByteBuffer passwordHash;
		private long nextCombination;
		private long areaLength;
	}

	@Data
	@AllArgsConstructor
	public static class WorkThiefMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private ActorRef thief;
	}

	@Data
	@NoArgsConstructor
	public static class RequestHashSetMessage implements Serializable {
		private static final long serialVersionUID = 2039203942748609598L;
	}

	@Data @AllArgsConstructor
	public static class HashSetDistributionMessage implements Serializable {
		private static final long serialVersionUID = 2039203942748609598L;
		HashSet<ByteBuffer> hashes;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
	private final ActorRef largeMessageProxy;
	private long registrationTime;
	private ActorRef localMaster;

	public enum WorkType {
		NO_WORK, HINT, PASSWORD
	}

	// Both Passwords and Hints
	private WorkType workType;
	private String alphabet;
	private long areaLength;

	// Only Hints
	private long nextPermutation;
	private HashSet<ByteBuffer> wantedHashes;

	// Only Passwords
	private long nextCombination;
	private ByteBuffer passwordHash;
	private long passwordLength;

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
	}

	private void handle(HintWorkMessage message) {
		this.workType = WorkType.HINT;
		this.alphabet = message.getAlphabet();
		this.areaLength = message.getAreaLength();
		this.nextPermutation = message.getNextPermutation();

		if (this.wantedHashes == null) {
			this.localMaster.tell(new RequestHashSetMessage(), this.self());
		} else {
			this.self().tell(new WorkShiftMessage(), this.self());
		}
	}

	private void handle(RequestHashSetMessage message) {
		if (this.wantedHashes != null) {
			this.sender().tell(new HashSetDistributionMessage(this.wantedHashes), this.self());
		} else {
			this.context().system().scheduler().scheduleOnce(
				Duration.ofMillis(100), this.self(), message, this.context().system().dispatcher(), this.sender()
			);
		}
	}

	private void handle(HashSetDistributionMessage message) {
		this.wantedHashes = message.getHashes();
		this.self().tell(new WorkShiftMessage(), this.self());
	}

	private void handle(CrackWorkMessage message) {
		this.workType = WorkType.PASSWORD;
		this.alphabet = message.getAlphabet();
		this.passwordLength = message.getPasswordLength();
		this.passwordHash = message.getPasswordHash();
		this.nextCombination = message.getNextCombination();
		this.areaLength = message.getAreaLength();

		this.self().tell(new WorkShiftMessage(), this.self());
	}

	private static final long workShiftLength = 100000; // TODO: Change this to seconds/milliseconds
	private static final long workShiftStealMultiplyer = 1;
	private void handle(WorkShiftMessage message) {
		// TODO do actual cracking work
		// TODO: while time spent < time budget for shift
		switch (this.workType) {
			case HINT:
				// TODO stuff
			case PASSWORD:
				// TODO password cracking
			case NO_WORK:
				return;
		}

		// stop after xxx seconds, email yourself
		if (areaLength == 0) {
			// TODO tell the master about it
			this.workType = WorkType.NO_WORK;
		}
        this.self().tell(new WorkShiftMessage(), this.self());
	}

	private void handle(WorkThiefMessage message) {
		if (areaLength >= workShiftLength * workShiftStealMultiplyer) {
			switch (this.workType) {
				case HINT:
					long stolenArea = areaLength / 2;
					this.areaLength -= stolenArea;
					long stolenNextPermutation = nextPermutation + areaLength;
					this.sender().tell(new HintWorkMessage(this.alphabet, stolenNextPermutation, stolenArea), this.self());
					break;
				case PASSWORD:
					stolenArea = this.areaLength / 2;
					this.areaLength -= stolenArea;
					long stolenNextCombination = nextCombination + areaLength;
					this.sender().tell(new CrackWorkMessage(this.alphabet, this.passwordLength, this.passwordHash, stolenNextCombination, stolenArea), this.self());
					break;
			}
		}
	}

	// TODO: Change to better hashing function
	private String hash(String characters) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
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