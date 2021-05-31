package de.hpi.ddm.singletons;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import java.nio.ByteBuffer;

public class ByteBufferSerializer extends Serializer<ByteBuffer> {

    @Override
    public void write(Kryo kryo, Output output, ByteBuffer object) {
        output.writeInt(object.capacity());
        output.write(object.array());
    }

    @Override
    public ByteBuffer read(Kryo kryo, Input input, Class<ByteBuffer> type) {
        final int length = input.readInt();
        final byte[] buffer = new byte[length];
        input.read(buffer, 0, length);

        return ByteBuffer.wrap(buffer, 0, length);
    }
}
