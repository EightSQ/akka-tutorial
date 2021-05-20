package de.hpi.ddm.actors;

import java.io.Serializable;
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
		this.passwordHashes = new HashSet<>();
		this.responsibleWorkers = new HashMap<>();
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

	@Data
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	@Data @NoArgsConstructor
	public static class RequestWorkMessage implements Serializable {
		private static final long serialVersionUID = 9201291601659723997L;
	}

	@Data @AllArgsConstructor
	public static class HintFoundMessage implements Serializable {
		private static final long serialVersionUID = 3302081601059923997L;
		private byte[] shaHash;
		private String hint;
	}

	@Data @AllArgsConstructor
	public static class PasswordFoundMessage implements Serializable {
		private static final long serialVersionUID = 3384529601659723997L;
		private byte[] shaHash;
		private String password;
	}

	@Data @AllArgsConstructor
	public static class NowWorkingOnHintMessage implements Serializable {
		private static final long serialVersionUID = 3384529601629839237L;
		private long nextPermutation;
		private long areaLength;
		private long hashesPerSecond;
	}

	@Data @AllArgsConstructor
	public static class NowWorkingOnPasswordMessage implements Serializable {
		private static final long serialVersionUID = 3384529601629839237L;
		private long nextPermutation;
		private long areaLength;
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
	HashSet<ByteBuffer> hintHashes;
	HashSet<ByteBuffer> passwordHashes;

	private HashMap<Address, ActorRef> responsibleWorkers;

	private long startTime;
	
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
				.match(NowWorkingOnHintMessage.class, this::handle)
				.match(NowWorkingOnPasswordMessage.class, this::handle)
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
		if (message.getLines().isEmpty()) this.inputDone = true;
		
		this.inputBuffer.addAll(message.getLines());
		if (this.inputBuffer.size() < 300 && !this.inputDone) { // TODO: Criterion for bufferin input, e.g. just 2 GB of data or so, instead of 300 lines
			// Fetch further lines from the Reader
			this.reader.tell(new Reader.ReadMessage(), this.self());
		} else {
			// Create hint cracking packages, we'll request new input if this.workDone == false, as soon as we have received all passwords in the future
			this.parseInputBuffer();
			this.distributeHints();
			this.startHintCracking();
		}
	}

	protected void handle(RequestWorkMessage message) {

	}
	
	protected void handle(HintFoundMessage message) {

	}

	protected void handle(PasswordFoundMessage message) {

	}

	protected void handle(NowWorkingOnHintMessage message) {

	}

	protected void handle(NowWorkingOnPasswordMessage message) {

	}

	protected void parseInputBuffer() {
		// Parse inputBuffer into HashSet (and also parseWords)
		for (String[] line : this.inputBuffer) {
			String id = line[0];
			String name = line[1];
			String alphabet = line[2];
			Long len = Long.parseLong(line[3]);
			byte[] passwordHash;
			try {
				passwordHash = Hex.decodeHex(line[4]);
				passwordHashes.add(ByteBuffer.wrap(passwordHash));
			} catch (DecoderException e) {
				e.printStackTrace();
				System.out.println("Failed to parse password hash: " + line[4]);
			}
			// TODO: Versionize all of this (we might read multiple batches)
			for (int i = 5; i < line.length; i++) {
				byte[] aHintHash;
				try {
					aHintHash = Hex.decodeHex(line[i]);
					hintHashes.add(ByteBuffer.wrap(aHintHash));
				} catch (DecoderException e) {
					e.printStackTrace();
					System.out.println("Failed to parse hint hash: " + line[4]);
				}
			}
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
			this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<Worker.HashSetDistributionMessage>(new Worker.HashSetDistributionMessage(serializableSet), localMaster), this.self());
		}
	}

	protected void startHintCracking() {
		// TODO
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

		this.sender().tell(new Worker.WelcomeMessage(localMaster), this.self());

		// TODO: Assign some work to registering workers. Note that the processing of the global task might have already started.
		// we need to think about how we deal with already started work...
	}
	
	protected void handle(Terminated message) {
		// TODO: Deal with local master death

		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.log().info("Unregistered {}", message.getActor());
	}

	public static ByteBuffer str_to_bb(String msg, Charset charset){
		return ByteBuffer.wrap(msg.getBytes(charset));
	}
}
