package de.hpi.ddm.actors;

import static org.junit.Assert.*;

import org.junit.Test;

public class CombinationWrapperTest {
    private static final String ALPHABET = "ABC";

    @Test
    public void testCombinationZero() {
        CombinationWrapper wrapper = new CombinationWrapper(ALPHABET, 0, 5);
        assertEquals("AAAAA", wrapper.toString());
    }

    @Test
    public void testCombinationTwo() {
        CombinationWrapper wrapper = new CombinationWrapper(ALPHABET, 2, 5);
        assertEquals("AAAAC", wrapper.toString());
    }

    @Test
    public void testLastCombination() {
        CombinationWrapper wrapper = new CombinationWrapper(ALPHABET, 80, 4);
        assertEquals("CCCC", wrapper.toString());
    }

    @Test
    public void testNextCombination() {
        CombinationWrapper wrapper = new CombinationWrapper(ALPHABET, 2, 5);
        wrapper.nextCombination();
        assertEquals("AAABA", wrapper.toString());
    }
}
