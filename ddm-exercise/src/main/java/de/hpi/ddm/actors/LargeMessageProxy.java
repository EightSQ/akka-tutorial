package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionStage;

import akka.NotUsed;
import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import akka.util.ByteString;
import akka.stream.Materializer;
import akka.stream.SourceRef;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.stream.javadsl.StreamRefs;
import de.hpi.ddm.singletons.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	private static final int chunkLength = 8192;

	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class LargeMessage<T> implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private T message;
		private ActorRef receiver;
	}

	/*@Data @NoArgsConstructor @AllArgsConstructor
	public static class BytesMessage<T> implements Serializable {
		private static final long serialVersionUID = 4057807743872319842L;
		private T bytes;
		private ActorRef sender;
		private ActorRef receiver;
	} */

	@Data @AllArgsConstructor
	public static class MessageOffer {
		final SourceRef<byte[]> sourceRef;
		private ActorRef sender;
		private ActorRef receiver;
		private int numberOfChunks;
	}


	/////////////////
	// Actor State //
	/////////////////
	Materializer mat = Materializer.matFromSystem(this.getContext().getSystem());

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	////////////////////
	// Actor Behavior //
	////////////////////
	
	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(LargeMessage.class, this::handle)
				.match(MessageOffer.class, this::handle)
				//.match(BytesMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(LargeMessage<?> largeMessage) {

		Object message = largeMessage.getMessage();
		ActorRef sender = this.sender();
		ActorRef receiver = largeMessage.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));
		
		// TODO: Implement a protocol that transmits the potentially very large message object.
		// The following code sends the entire message wrapped in a BytesMessage, which will definitely fail in a distributed setting if the message is large!
		// Solution options:
		// a) Split the message into smaller batches of fixed size and send the batches via ...
		//    a.a) self-build send-and-ack protocol (see Master/Worker pull propagation), or
		//    a.b) Akka streaming using the streams build-in backpressure mechanisms.
		// b) Send the entire message via Akka's http client-server component.
		// c) Other ideas ...
		// Hints for splitting:
		// - To split an object, serialize it into a byte array and then send the byte array range-by-range (tip: try "KryoPoolSingleton.get()").
		// - If you serialize a message manually and send it, it will, of course, be serialized again by Akka's message passing subsystem.
		// - But: Good, language-dependent serializers (such as kryo) are aware of byte arrays so that their serialization is very effective w.r.t. serialization time and size of serialized data.


		byte[] serializedMessage = KryoPoolSingleton.get().toBytesWithClass(message); // TODO: Compression!

		List<byte[]> chunks = new ArrayList<byte[]>();
		for (int chunkStart = 0; chunkStart < serializedMessage.length; chunkStart += chunkLength) {
			int chunkEnd = Math.min(chunkStart + chunkLength, serializedMessage.length);
			chunks.add(Arrays.copyOfRange(serializedMessage, chunkStart, chunkEnd));
		}

		Source<byte[], NotUsed> source = Source.from(chunks);
		SourceRef<byte[]> sourceRef = source.runWith(StreamRefs.sourceRef(), mat);

		// Send StreamRef to receiver
		receiverProxy.tell(new MessageOffer(sourceRef, sender, receiver, chunks.size()), this.getSelf());
	}

	private void handle(MessageOffer messageOffer) {
		// get SourceRef out of MessageOffer
        SourceRef<byte[]> sourceRef = messageOffer.sourceRef;
		Source<byte[], NotUsed> source = sourceRef.getSource();

        // read stream data (until stream closed)
		//byte[] messageBytes = new byte[messageOffer.getNumberOfChunks() * chunkLength]; // TODO: Maybe this breaks, maybe we need the exact message length, so Kryo doesn't get confused
		//ByteBuffer result = ByteBuffer.wrap(messageBytes);

		Sink<byte[], CompletionStage<ByteString>> sink = Sink.<ByteString, byte[]>fold(ByteString.empty(), (aggr, next) -> aggr.concat(ByteString.fromArray(next)));
		source.runWith(sink, mat).whenCompleteAsync((byteString, throwable) -> {
			// decompress/deserialize
			Object unpackedMessage = KryoPoolSingleton.get().fromBytes(byteString.toArray());

			// send the unpacked message to the real receiver
			messageOffer.getReceiver().tell(unpackedMessage, messageOffer.getSender());
		});

	}
}
