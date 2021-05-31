package de.hpi.ddm.actors;

import java.io.*;
import java.util.concurrent.CompletionStage;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

import akka.NotUsed;
import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import akka.stream.*;
import akka.stream.javadsl.*;
import akka.util.ByteString;
import de.hpi.ddm.singletons.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	private static final int chunkLength = 65536;

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

	@Data @AllArgsConstructor
	public static class MessageOffer implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private SourceRef<ByteString> sourceRef;
		private ActorRef sender;
		private ActorRef receiver;
	}


	/////////////////
	// Actor State //
	/////////////////
	private Materializer mat = Materializer.matFromSystem(this.getContext().getSystem());

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
		byte[] serializedObject = KryoPoolSingleton.get().toBytesWithClass(message);
		if (serializedObject != null) {
			byte[] serializedMessage = compress(serializedObject);

			if (serializedMessage != null) {
				ByteArrayInputStream serializedStream = new ByteArrayInputStream(serializedMessage);
				Source<ByteString, CompletionStage<IOResult>> source = StreamConverters.fromInputStream(() -> serializedStream, chunkLength);
				SourceRef<ByteString> sourceRef = source.runWith(StreamRefs.sourceRef(), this.mat);
				receiverProxy.tell(new MessageOffer(sourceRef, sender, receiver), this.getSelf());
			} else {
				this.log().error("Could not compress message.");
			}
		} else {
			this.log().error("Could not serialize message.");
		}


	}

	private void handle(MessageOffer messageOffer) {
		// get SourceRef out of MessageOffer
        SourceRef<ByteString> sourceRef = messageOffer.sourceRef;
		Source<ByteString, NotUsed> source = sourceRef.getSource();

        // create a sink
		Sink<ByteString, CompletionStage<ByteString>> sink = Sink.<ByteString, ByteString>fold(ByteString.empty(), ByteString::concat);

		// and drain the source into it
		source.runWith(sink, this.mat).whenCompleteAsync((byteString, throwable) -> {
			// decompress/deserialize
			byte[] decompressedMessage = decompress(byteString.toArray());

            if (decompressedMessage != null) {
				Object unpackedMessage = KryoPoolSingleton.get().fromBytes(decompressedMessage);

				// send the unpacked message to the real receiver
				messageOffer.getReceiver().tell(unpackedMessage, messageOffer.getSender());
			} else {
				this.log().error("Could not decompress message.");
			}
		});
	}

	///////////////////////
	// COMPRESSION UTILS //
	///////////////////////

	private byte[] compress(byte[] in) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			DeflaterOutputStream defl = new DeflaterOutputStream(out);
			defl.write(in);
			defl.flush();
			defl.close();

			return out.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private byte[] decompress(byte[] in) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream infl = new InflaterOutputStream(out);
			infl.write(in);
			infl.flush();
			infl.close();

			return out.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}


}
