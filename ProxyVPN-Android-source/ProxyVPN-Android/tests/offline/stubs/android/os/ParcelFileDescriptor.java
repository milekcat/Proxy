package android.os;
import java.io.FileDescriptor;
import java.io.IOException;
public class ParcelFileDescriptor implements AutoCloseable {
    public FileDescriptor getFileDescriptor() { return new FileDescriptor(); }
    public void close() throws IOException { }
}
