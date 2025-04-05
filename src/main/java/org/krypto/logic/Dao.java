package org.krypto.logic;

public interface Dao<T> extends AutoCloseable {
    T read();
    void write(T obj);

}
