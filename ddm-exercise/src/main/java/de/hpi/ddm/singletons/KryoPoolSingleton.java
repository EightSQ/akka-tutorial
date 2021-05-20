package de.hpi.ddm.singletons;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.twitter.chill.KryoInstantiator;
import com.twitter.chill.KryoPool;

import java.nio.ByteBuffer;

public class KryoPoolSingleton {

	private static final int POOL_SIZE = 10;
	private static final KryoPool kryo = KryoPool.withByteArrayOutputStream(POOL_SIZE, new KryoInstantiator());
	
	public static KryoPool get() {
		return kryo;
	}
}
