package de.hpi.ddm.actors;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import akka.actor.*;
import de.hpi.ddm.structures.BloomFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Master extends AbstractLoggingActor {

	// TODOs: work stealing heuristics

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "master";

	public static Props props(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		return Props.create(Master.class, () -> new Master(reader, collector, welcomeData));
	}

	public Master(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		this.welcomeData = welcomeData;
		this.inputBuffer = new ArrayList<>();
		this.inputDone = false;
		this.hintHashes = new HashSet<>();
		this.responsibleWorkers = new HashMap<>();
		this.crackedHints = new HashMap<>();
		this.workersWaiting = new ArrayList<>();
		this.workPackageMap = new HashMap<>();
		this.openPackages = new ArrayList<>();
		this.readyPasswordWorkPackages = new ArrayList<>();
		this.crackingStarted = false;
		this.passwordHintMap = new HashMap<>();
		this.passwordProgress = new HashMap<>();
		this.hintToPasswords = new HashMap<>();
		this.passwordLength = -1337;
		this.passwordIDMap = new HashMap<>();
		this.foundPasswords = new HashSet<>();
		this.batchNumber = 0;
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	@Data @NoArgsConstructor
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	@Data @NoArgsConstructor
	public static class RequestWorkMessage implements Serializable {
		private static final long serialVersionUID = 9201291601659723997L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HintFoundMessage implements Serializable {
		private static final long serialVersionUID = 3302081601059923997L;
		private byte[] shaHash;
		private Character hint;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PasswordFoundMessage implements Serializable {
		private static final long serialVersionUID = 3384529601659723997L;
		private byte[] shaHash;
		private String password;
	}


	@Data @NoArgsConstructor @AllArgsConstructor
	public static abstract class WorkPackage implements Serializable {
		public abstract Worker.WorkType getType();
		public abstract Object createMessage();
		protected long nextTry;
		protected long areaLeft;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HintWorkPackage extends WorkPackage implements Serializable {
		@Override
		public Worker.WorkType getType() {
			return Worker.WorkType.HINT;
		}

		@Override
		public Object createMessage() {
			return new Worker.HintWorkMessage(this.alphabet, this.nextTry, this.areaLeft, this.wantedHashesVersion);
		}

		private String alphabet;
		private int wantedHashesVersion;

		public HintWorkPackage(long nextTry, long areaLeft, String alphabet, int wantedHashesVersion) {
			super(nextTry, areaLeft);
			this.alphabet = alphabet;
			this.wantedHashesVersion = wantedHashesVersion;
		}
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PasswordWorkPackage extends WorkPackage implements Serializable {
		@Override
		public Worker.WorkType getType() {
			return Worker.WorkType.PASSWORD;
		}

		public Object createMessage() {
			return new Worker.CrackWorkMessage(this.postHintAlphabet, this.passwordLength, this.passwordHash, this.nextTry, this.areaLeft);
		}

		private String postHintAlphabet;
		private byte[] passwordHash;
		private long passwordLength;

		public PasswordWorkPackage(long nextTry, long areaLeft, String postHintAlphabet, byte[] passwordHash, long passwordLength) {
			super(nextTry, areaLeft);
			this.postHintAlphabet = postHintAlphabet;
			this.passwordHash = passwordHash;
			this.passwordLength = passwordLength;
		}
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class NowWorkingOnMessage implements Serializable {
		private static final long serialVersionUID = 3384529601629839237L;
		private WorkPackage workPackage;
		private long hashesPerSecond;
	}


	/////////////////
	// Actor State //
	/////////////////

	private final ActorRef reader;
	private final ActorRef collector;
	private final List<ActorRef> workers;
	private final ActorRef largeMessageProxy;
	private final BloomFilter welcomeData;

	private List<String> tableColumns;
	private List<String[]> inputBuffer;
	private Boolean inputDone;
	private HashSet<ByteBuffer> hintHashes;
	private HashMap<ByteBuffer, Character> crackedHints;
	private String alphabet;

	private HashMap<Address, ActorRef> responsibleWorkers;
	private HashMap<ActorRef, WorkPackage> workPackageMap;
	private List<ActorRef> workersWaiting;
	private List<WorkPackage> openPackages;
	private List<WorkPackage> readyPasswordWorkPackages;

	private HashMap<ByteBuffer, List<ByteBuffer>> passwordHintMap;
	private HashMap<ByteBuffer, List<Integer>> passwordIDMap;

	private HashMap<ByteBuffer, Integer> passwordProgress;
	private HashMap<ByteBuffer, Set<ByteBuffer>> hintToPasswords;
	private HashSet<ByteBuffer> foundPasswords;

	private Boolean crackingStarted;

	private long startTime;
	private long passwordLength;

	private int totalPasswords;
	private int passwordsInHintCracking;
	private int passwordsInPWCracking;
	private int passwordsDone;

	private int batchNumber;
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(StartMessage.class, this::handle)
				.match(BatchMessage.class, this::handle)
				.match(Terminated.class, this::handle)
				.match(RegistrationMessage.class, this::handle)
				.match(RequestWorkMessage.class, this::handle)
				.match(HintFoundMessage.class, this::handle)
				.match(PasswordFoundMessage.class, this::handle)
				.match(NowWorkingOnMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();
		
		this.reader.tell(new Reader.ReadMessage(), this.self());
	}
	
	protected void handle(BatchMessage message) {
		// TODO: This is where the task begins:
		// - The Master received the first batch of input records.
		// - To receive the next batch, we need to send another ReadMessage to the reader.
		// - If the received BatchMessage is empty, we have seen all data for this task.
		// - We need a clever protocol that forms sub-tasks from the seen records, distributes the tasks to the known workers and manages the results.
		//   -> Additional messages, maybe additional actors, code that solves the subtasks, ...
		//   -> The code in this handle function needs to be re-written.
		// - Once the entire processing is done, this.terminate() needs to be called.
		
		// Info: Why is the input file read in batches?
		// a) Latency hiding: The Reader is implemented such that it reads the next batch of data from disk while at the same time the requester of the current batch processes this batch.
		// b) Memory reduction: If the batches are processed sequentially, the memory consumption can be kept constant; if the entire input is read into main memory, the memory consumption scales at least linearly with the input size.
		// - It is your choice, how and if you want to make use of the batched inputs. Simply aggregate all batches in the Master and start the processing afterwards, if you wish.

		if (this.inputDone) return;
		if (message.getLines().isEmpty()) {
			this.inputDone = true;
		} else {
			this.inputBuffer.addAll(message.getLines());
		}

		if (this.inputBuffer.size() < 300 && !this.inputDone) {
			// Fetch further lines from the Reader
			this.reader.tell(new Reader.ReadMessage(), this.self());
		} else {
			// Create hint cracking packages, we'll request new input if this.workDone == false, as soon as we have received all passwords in the future
			this.batchNumber++;
			this.parseInputBuffer();
			this.distributeHints();
			this.startHintCracking();
			this.inputBuffer.clear();
		}
	}



	Optional<ActorRef> findWorkTheftVictim(Worker.WorkType workType) {
		for (Map.Entry<ActorRef, WorkPackage> workShift : this.workPackageMap.entrySet()) {
			WorkPackage workPackage = workShift.getValue();
			if (workPackage.getType() == workType && workPackage.getAreaLeft() > Worker.MINIMUM_WORK_SPLITTABLE) {
				return Optional.of(workShift.getKey());
			}
		}
		return Optional.empty();
	}

	// 1. open packages from terminated workers (hint or password)
	// 2. work stealing (hint)
	// 3. distribute password work package
	// 4. work stealing (password)
	// 5. add to workersWaiting
	protected void handle(RequestWorkMessage message) {
		//System.out.println("Received RequestWorkMessage by worker "+ this.sender().path().toString());
		Optional<ActorRef> theftVictim;
		Boolean workStealingEnabled = true;
		if (this.openPackages.size() > 0) {
			//System.out.println("Sending open work package by worker "+ this.sender().path().toString());
			WorkPackage pkg = this.openPackages.get(0);
			this.sender().tell(pkg.createMessage(), this.getSelf());
			workPackageMap.put(this.sender(), pkg);
			this.openPackages.remove(0);
		} else if ((theftVictim = this.findWorkTheftVictim(Worker.WorkType.HINT)).isPresent() && workStealingEnabled) {
			//System.out.println("Letting "+ this.sender().path().toString() + " steal from " + theftVictim.get().path().toString());
			theftVictim.get().tell(new Worker.WorkThiefMessage(), this.sender());
		} else if (!this.readyPasswordWorkPackages.isEmpty()) {
			//System.out.println("Sending new password work package to worker "+ this.sender().path().toString());
			PasswordWorkPackage pkg = (PasswordWorkPackage) this.readyPasswordWorkPackages.get(0);
			this.sender().tell(pkg.createMessage(), this.getSelf());
			workPackageMap.put(this.sender(), pkg);
			this.readyPasswordWorkPackages.remove(0);
		} else if ((theftVictim = this.findWorkTheftVictim(Worker.WorkType.PASSWORD)).isPresent() && workStealingEnabled) {
			//System.out.println("Create a thief of password work: "+ this.sender().path().toString());
			theftVictim.get().tell(new Worker.WorkThiefMessage(), this.sender());
		} else if (!this.workersWaiting.contains(this.sender())) {
			System.out.println("Sending worker "+ this.sender().path().toString() + " to sleep. Sleeping workers: " + (this.workersWaiting.size() + 1) + "/" + this.workers.size() + ", Passwords Done: " + this.passwordsDone + "/" +  this.totalPasswords);
			this.workersWaiting.add(this.sender());

			/*for (ActorRef worker : this.workers) {
				if (!this.workersWaiting.contains(worker)) {
					System.out.println("Worker " + worker.path().toString() + " is still running.");
				}
			}*/

			if (this.workersWaiting.size() >= this.workers.size()) {
				if (this.inputDone && this.passwordsDone == this.totalPasswords) {
					this.terminate();
				} else {
					if (this.inputDone && this.passwordsDone < this.totalPasswords) {
						System.err.println("We have a problem, all workers sleep, but we're not done with our batch. Terminating anyways.");
						this.terminate();
					} else {
						// Read some more work from the csv
						this.reader.tell(new Reader.ReadMessage(), this.self());
					}
				}
			}

		}

		this.printProgress();
	}
	
	private void preparePasswordForCracking(ByteBuffer passwordHash) {
		String passwordAlphabet = this.alphabet;
		this.passwordsInHintCracking--;
		for (ByteBuffer hintHash : passwordHintMap.get(passwordHash)) {
			Character hint = crackedHints.get(hintHash);
			if (hint != null) {
				passwordAlphabet = passwordAlphabet.replace(hint.toString(), "");
			} else {
				System.err.println("Hint " + Hex.encodeHexString(hintHash.array()) + " for password " + Hex.encodeHexString(passwordHash.array()) + " is null!");
				System.err.println("All hints for that password:");
				for (ByteBuffer hintHash2 : passwordHintMap.get(passwordHash)) {
					if (!crackedHints.containsKey(hintHash2)) {
						System.err.println(Hex.encodeHexString(hintHash2.array()) + " doesn't have any solution!");
					}
					Character hint2 = crackedHints.get(hintHash2);
					if (hint2 != null) {
						System.err.println(Hex.encodeHexString(hintHash2.array()) + "=" + hint2.toString());
					} else {
						System.err.println(Hex.encodeHexString(hintHash2.array()) + "=null");

					}
				}
				System.err.println("");

			}
		}
		long numberOfWorkers = this.workers.size();
		long maxCombination = BigInteger.valueOf(passwordAlphabet.length()).pow((int) this.passwordLength).longValue();
		long standardAreaLength = maxCombination / numberOfWorkers;
		long nextCombination = 0;

		// TODO only split if search space is big
		// without splitting the password search space up
		//readyPasswordWorkPackages.add(new PasswordWorkPackage(nextCombination, maxCombination, passwordAlphabet, passwordHash.array(), this.passwordLength));

		for (int i = 0; i < numberOfWorkers; i++) {
			long areaLength = standardAreaLength;
			if (i == numberOfWorkers - 1) {
				// the last one gets the rest
				areaLength = maxCombination - nextCombination;
			}

			readyPasswordWorkPackages.add(new PasswordWorkPackage(nextCombination, areaLength, passwordAlphabet, passwordHash.array(), this.passwordLength));
			nextCombination += standardAreaLength;
		}
		this.passwordsInPWCracking++;
		this.notifyAllWaitingWorkers();
		//System.out.println("Password " + Hex.encodeHexString(passwordHash.array()) + " is ready to be cracked, got dem hints!");
	}

	protected void handle(HintFoundMessage message) {
		if (!this.crackedHints.containsKey(ByteBuffer.wrap(message.getShaHash()))) {
			this.crackedHints.put(ByteBuffer.wrap(message.getShaHash()), message.getHint());
			Set<ByteBuffer> passwords = hintToPasswords.get(ByteBuffer.wrap(message.getShaHash()));
			for (ByteBuffer passwordHash : passwords) {
				passwordProgress.put(passwordHash, passwordProgress.get(passwordHash) - 1);
				if (passwordProgress.get(passwordHash) < 1) {
					this.preparePasswordForCracking(passwordHash);
				}
				//System.out.println("We cracked a hint! Hash: " + Hex.encodeHexString(passwordHash.array()) + " Solution: " + message.getHint() + " Progress: " + passwordProgress.get(passwordHash));
			}
		} else {
			//System.out.println("We already cracked the hint! Hash: " + Hex.encodeHexString(message.getShaHash()) + " Solution: " + message.getHint() + " Old Solution: " + this.crackedHints.get(ByteBuffer.wrap(message.getShaHash())));
		}
		this.printProgress();

	}

	private void printProgress() {
		//System.out.println("Progress: " + this.passwordsInHintCracking + " (Hintcracking) / " + this.passwordsInPWCracking + " (PW Cracking) / " + this.passwordsDone + " (Done) (Total " + this.totalPasswords + ") Sleeping Workers: " + this.workersWaiting.size() + "/" + this.workers.size());
	}
	protected void handle(PasswordFoundMessage message) {
		ByteBuffer passwordHash = ByteBuffer.wrap(message.shaHash);
		// TODO: Deal with the fact what happens if two users have the same password


		if (!this.foundPasswords.contains(passwordHash)) {
			for (int id : this.passwordIDMap.get(passwordHash)) {
				this.passwordsDone++;
				this.passwordsInPWCracking--;
				Collector.ResultObject res = new Collector.ResultObject(id, message.getPassword());
				this.collector.tell(new Collector.CollectMessage(res), this.getSelf());
			}
			//System.out.println("We cracked a password! Hash: " + Hex.encodeHexString(message.shaHash) + " Solution: " + message.getPassword());
			this.foundPasswords.add(passwordHash);

		} else {
			System.out.println("We cracked a password that we already did crack! Hash: " + Hex.encodeHexString(message.shaHash) + " Solution: " + message.getPassword());
		}

		this.printProgress();
	}

	protected void handle(NowWorkingOnMessage message) {
		workPackageMap.put(this.sender(), message.workPackage);
	}

	protected void parseInputBuffer() {
		// Parse inputBuffer into HashSet (and also parseWords)
		this.totalPasswords = 0;
		// TODO reset all our stuff here
		this.hintHashes = new HashSet<>();
		this.crackedHints = new HashMap<>();
		this.passwordIDMap = new HashMap<>();
		this.passwordsInHintCracking = 0;
		this.passwordsInPWCracking = 0;
		this.passwordsDone = 0;
		this.crackedHints = new HashMap<>();
		this.foundPasswords = new HashSet<>();
		this.workersWaiting = new ArrayList<>();
		this.workPackageMap = new HashMap<>();
		this.hintToPasswords = new HashMap<>();
		this.readyPasswordWorkPackages = new ArrayList<>();
		this.passwordHintMap = new HashMap<>();
		this.totalPasswords = 0;
		this.passwordProgress = new HashMap<>();

		for (String[] line : this.inputBuffer) {
			String id = line[0];
			String name = line[1];
			this.alphabet = line[2];
			this.passwordLength = Long.parseLong(line[3]);
			this.totalPasswords++;
			this.passwordsInHintCracking++;
			byte[] passwordHash = new byte[0];
			try {
				passwordHash = Hex.decodeHex(line[4]);
				passwordHintMap.put(ByteBuffer.wrap(passwordHash), new ArrayList<>());

				passwordProgress.put(ByteBuffer.wrap(passwordHash), line.length - 5);
				if (!passwordIDMap.containsKey(ByteBuffer.wrap(passwordHash))) {
					passwordIDMap.put(ByteBuffer.wrap(passwordHash), new ArrayList<>());
				}
				passwordIDMap.get(ByteBuffer.wrap(passwordHash)).add(Integer.valueOf(id));
			} catch (DecoderException e) {
				e.printStackTrace();
				System.out.println("Failed to parse password hash: " + line[4]);
			}
			for (int i = 5; i < line.length; i++) {
				byte[] aHintHash;
				try {
					aHintHash = Hex.decodeHex(line[i]);
					this.hintHashes.add(ByteBuffer.wrap(aHintHash));
					if (!hintToPasswords.containsKey(ByteBuffer.wrap(aHintHash))) {
						hintToPasswords.put(ByteBuffer.wrap(aHintHash), new HashSet<>());
					}
					hintToPasswords.get(ByteBuffer.wrap(aHintHash)).add(ByteBuffer.wrap(passwordHash));
					passwordHintMap.get(ByteBuffer.wrap(passwordHash)).add(ByteBuffer.wrap(aHintHash));
				} catch (DecoderException e) {
					e.printStackTrace();
					System.out.println("Failed to parse hint hash: " + line[4]);
				}
			}
		}

		HashSet<Integer> uniqueVals = new HashSet<>(passwordProgress.values());
		for (Integer val : uniqueVals) {
			System.out.println("----------------------- VAL: " + val);
		}

	}

	protected void distributeHints() {
		// Send HashSet to one worker per ActorSystem via LargeMessageProxy. These distribute the HashSet then internally without the LMP?
		// we need to convert the ByteBuffers (that we need because a hashset of byte[] doesn't wor ) to byte[] (kill me)

		HashSet<byte[]> serializableSet = new HashSet<>();
		for (ByteBuffer b : this.hintHashes) {
			serializableSet.add(b.array());
		}

		for (ActorRef localMaster : this.responsibleWorkers.values()) {
			System.out.println("Telling localMaster " + localMaster.path().toString() + " about the hashes!");
			this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<Worker.HashSetDistributionMessage>(new Worker.HashSetDistributionMessage(serializableSet, this.batchNumber), localMaster), this.self());
		}
	}

	protected void startHintCracking() {
		long numberOfWorkers = this.workers.size();
		long maxPermutation = factorial(this.alphabet.length());
		long nextPermutation = 0;
		long standardAreaLength = (maxPermutation / numberOfWorkers);
		for (int i = 0; i < numberOfWorkers; i++) {
			long areaLength = standardAreaLength;
			if (i == numberOfWorkers - 1) {
				// the last one gets the rest
				areaLength = maxPermutation - nextPermutation + 1;
			}

			ActorRef worker = this.workers.get(i);
			//System.out.println("Worker " + worker.path().toString() + " gets permutations " + nextPermutation + "-" + (nextPermutation+areaLength) + " out of " + maxPermutation);

			HintWorkPackage pkg = new HintWorkPackage(nextPermutation, areaLength, this.alphabet, this.batchNumber);

			worker.tell(pkg.createMessage(), this.getSelf());
			workPackageMap.put(worker, pkg);
			nextPermutation += standardAreaLength;
		}

		this.crackingStarted = true;
	}

	private long factorial(long n) {
		if (n==1) return n;
		return n * factorial(n-1);
	}
	
	protected void terminate() {
		this.collector.tell(new Collector.PrintMessage(), this.self());
		
		this.reader.tell(PoisonPill.getInstance(), ActorRef.noSender());
		this.collector.tell(PoisonPill.getInstance(), ActorRef.noSender());
		
		for (ActorRef worker : this.workers) {
			this.context().unwatch(worker);
			worker.tell(PoisonPill.getInstance(), ActorRef.noSender());
		}
		
		this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
		
		long executionTime = System.currentTimeMillis() - this.startTime;
		this.log().info("Algorithm finished in {} ms", executionTime);
	}

	protected void handle(RegistrationMessage message) {
		this.context().watch(this.sender());
		this.workers.add(this.sender());

		ActorRef localMaster;
		// if we don't know this ActorSystem (represented by an Address) yet
		if (!this.responsibleWorkers.containsKey(this.sender().path().address())) {
			this.responsibleWorkers.put(this.sender().path().address(), this.sender());
			this.log().info("Registered {} as master worker for system {}", this.sender(), this.sender().path().address());
			localMaster = this.sender();
		} else {
			this.log().info("Registered {} as slave worker for system {}", this.sender(), this.sender().path().address());
			localMaster = this.responsibleWorkers.get(this.sender().path().address());
		}

		this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<Worker.WelcomeMessage>(new Worker.WelcomeMessage(this.welcomeData), this.sender()), this.self());
		this.sender().tell(new Worker.MasterInformationMessage(localMaster), this.self());

		// Assign some work to registering workers if processing of the global task might have already started.

		if (this.crackingStarted) {
			if (this.sender() == localMaster) {
				HashSet<byte[]> serializableSet = new HashSet<>();
				for (ByteBuffer b : this.hintHashes) {
					serializableSet.add(b.array());
				}

				this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<Worker.HashSetDistributionMessage>(new Worker.HashSetDistributionMessage(serializableSet, this.batchNumber), localMaster), this.self());
			} else {
				this.workersWaiting.add(this.sender());
				this.notifyAllWaitingWorkers();
			}
		}
	}

	private void notifyAllWaitingWorkers() {
		// notify all our sleeping workers
		for (ActorRef actor : this.workersWaiting) {
			this.self().tell(new RequestWorkMessage(), actor);
		}
		this.workersWaiting.clear();
	}

	protected void handle(Terminated message) {
		// TODO: Deal with local master death
		this.openPackages.add(this.workPackageMap.get(this.getSender()));
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.log().info("Unregistered {}", message.getActor());
		this.notifyAllWaitingWorkers();
	}

	public static ByteBuffer str_to_bb(String msg, Charset charset) {
		return ByteBuffer.wrap(msg.getBytes(charset));
	}
}
