package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import akka.actor.AbstractLoggingActor;
import akka.actor.Props;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Collector extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "collector";

	public static Props props() {
		return Props.create(Collector.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class CollectMessage implements Serializable {
		private static final long serialVersionUID = -102767440935270949L;
		private ResultObject resultObject;
	}

	@Data
	public static class PrintMessage implements Serializable {
		private static final long serialVersionUID = -267778464637901383L;
	}
	
	/////////////////
	// Actor State //
	/////////////////

	@Data @AllArgsConstructor
	public static class ResultObject implements Comparable<ResultObject>, Serializable {
		@Override
		public int compareTo(ResultObject o) {
			int res = this.id - o.id;
			if (res == 0) {
				res = this.crackedPassword.compareTo(o.crackedPassword);
			}
			return res;
		}

		private int id;
		private String crackedPassword;
	}
	private List<ResultObject> results = new ArrayList<>();
	
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
				.match(CollectMessage.class, this::handle)
				.match(PrintMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	protected void handle(CollectMessage message) {
		this.results.add(message.getResultObject());
	}
	
	protected void handle(PrintMessage message) {
		Collections.sort(this.results);
		this.results.forEach(resultObject -> this.log().info("id: {}, password: {}", resultObject.getId(), resultObject.getCrackedPassword()));
	}
}
