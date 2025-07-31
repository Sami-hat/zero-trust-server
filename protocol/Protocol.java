package protocol;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Protocol message definitions for client-server communication
 */
public class Protocol {

    // Protocol version
    public static final int PROTOCOL_VERSION = 1;

    // Message types
    public enum MessageType {
        // Authentication
        AUTH_REQUEST(0x01),
        AUTH_RESPONSE(0x02),
        AUTH_CHALLENGE(0x03),

        // File operations
        UPLOAD_REQUEST(0x10),
        UPLOAD_RESPONSE(0x11),
        DOWNLOAD_REQUEST(0x12),
        DOWNLOAD_RESPONSE(0x13),
        DELETE_REQUEST(0x14),
        DELETE_RESPONSE(0x15),

        // Sharing operations
        SHARE_REQUEST(0x20),
        SHARE_RESPONSE(0x21),
        REVOKE_REQUEST(0x22),
        REVOKE_RESPONSE(0x23),

        // Metadata operations
        LIST_REQUEST(0x30),
        LIST_RESPONSE(0x31),
        INFO_REQUEST(0x32),
        INFO_RESPONSE(0x33),

        // Control messages
        PING(0x40),
        PONG(0x41),
        ERROR(0x42),
        QUIT(0x43),

        // Batch operations
        BATCH_START(0x50),
        BATCH_END(0x51),
        BATCH_ABORT(0x52);

        private final byte code;

        MessageType(int code) {
            this.code = (byte) code;
        }

        public byte getCode() {
            return code;
        }

        public static MessageType fromCode(byte code) {
            for (MessageType type : values()) {
                if (type.code == code) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown message type: " + code);
        }
    }

    // Response codes
    public enum ResponseCode {
        SUCCESS(0x00),
        UNAUTHORIZED(0x01),
        NOT_FOUND(0x02),
        ALREADY_EXISTS(0x03),
        INVALID_REQUEST(0x04),
        SERVER_ERROR(0x05),
        QUOTA_EXCEEDED(0x06),
        RATE_LIMITED(0x07),
        OPERATION_FAILED(0x08);

        private final byte code;

        ResponseCode(int code) {
            this.code = (byte) code;
        }

        public byte getCode() {
            return code;
        }

        public static ResponseCode fromCode(byte code) {
            for (ResponseCode rc : values()) {
                if (rc.code == code) {
                    return rc;
                }
            }
            throw new IllegalArgumentException("Unknown response code: " + code);
        }
    }

    // Base message class
    public static abstract class Message implements Serializable {
        protected final MessageType type;
        protected final long timestamp;
        protected final String messageId;

        public Message(MessageType type) {
            this.type = type;
            this.timestamp = System.currentTimeMillis();
            this.messageId = UUID.randomUUID().toString();
        }

        public MessageType getType() {
            return type;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getMessageId() {
            return messageId;
        }

        public abstract byte[] serialize() throws IOException;

        public static Message deserialize(byte[] data) throws IOException, ClassNotFoundException {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            byte typeCode = buffer.get();
            MessageType type = MessageType.fromCode(typeCode);

            switch (type) {
                case UPLOAD_REQUEST:
                    return UploadRequest.deserializeFrom(buffer);
                case UPLOAD_RESPONSE:
                    return UploadResponse.deserializeFrom(buffer);
                case DOWNLOAD_REQUEST:
                    return DownloadRequest.deserializeFrom(buffer);
                case DOWNLOAD_RESPONSE:
                    return DownloadResponse.deserializeFrom(buffer);
                case ERROR:
                    return ErrorMessage.deserializeFrom(buffer);
                default:
                    throw new IOException("Unsupported message type for deserialization: " + type);
            }
        }
    }

    // Upload request message
    public static class UploadRequest extends Message {
        private final String filename;
        private final long fileSize;
        private final byte[] checksum;
        private final Map<String, String> metadata;

        public UploadRequest(String filename, long fileSize, byte[] checksum) {
            super(MessageType.UPLOAD_REQUEST);
            this.filename = filename;
            this.fileSize = fileSize;
            this.checksum = checksum;
            this.metadata = new HashMap<>();
        }

        public String getFilename() {
            return filename;
        }

        public long getFileSize() {
            return fileSize;
        }

        public byte[] getChecksum() {
            return checksum.clone();
        }

        public void addMetadata(String key, String value) {
            metadata.put(key, value);
        }

        @Override
        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(type.getCode());
            dos.writeLong(timestamp);
            dos.writeUTF(messageId);
            dos.writeUTF(filename);
            dos.writeLong(fileSize);
            dos.writeInt(checksum.length);
            dos.write(checksum);

            // Write metadata
            dos.writeInt(metadata.size());
            for (Map.Entry<String, String> entry : metadata.entrySet()) {
                dos.writeUTF(entry.getKey());
                dos.writeUTF(entry.getValue());
            }

            return baos.toByteArray();
        }

        public static UploadRequest deserializeFrom(ByteBuffer buffer) throws IOException {
            long timestamp = buffer.getLong();
            String messageId = readString(buffer);
            String filename = readString(buffer);
            long fileSize = buffer.getLong();

            int checksumLength = buffer.getInt();
            byte[] checksum = new byte[checksumLength];
            buffer.get(checksum);

            UploadRequest request = new UploadRequest(filename, fileSize, checksum);

            // Read metadata
            int metadataSize = buffer.getInt();
            for (int i = 0; i < metadataSize; i++) {
                String key = readString(buffer);
                String value = readString(buffer);
                request.addMetadata(key, value);
            }

            return request;
        }
    }

    // Upload response message
    public static class UploadResponse extends Message {
        private final ResponseCode responseCode;
        private final String message;
        private final String fileId;

        public UploadResponse(ResponseCode responseCode, String message, String fileId) {
            super(MessageType.UPLOAD_RESPONSE);
            this.responseCode = responseCode;
            this.message = message;
            this.fileId = fileId;
        }

        public ResponseCode getResponseCode() {
            return responseCode;
        }

        public String getMessage() {
            return message;
        }

        public String getFileId() {
            return fileId;
        }

        @Override
        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(type.getCode());
            dos.writeLong(timestamp);
            dos.writeUTF(messageId);
            dos.writeByte(responseCode.getCode());
            dos.writeUTF(message != null ? message : "");
            dos.writeUTF(fileId != null ? fileId : "");

            return baos.toByteArray();
        }

        public static UploadResponse deserializeFrom(ByteBuffer buffer) throws IOException {
            long timestamp = buffer.getLong();
            String messageId = readString(buffer);
            ResponseCode code = ResponseCode.fromCode(buffer.get());
            String message = readString(buffer);
            String fileId = readString(buffer);

            return new UploadResponse(code, message.isEmpty() ? null : message,
                    fileId.isEmpty() ? null : fileId);
        }
    }

    // Download request message
    public static class DownloadRequest extends Message {
        private final String filename;
        private final long offset;
        private final long length;

        public DownloadRequest(String filename) {
            this(filename, 0, -1);
        }

        public DownloadRequest(String filename, long offset, long length) {
            super(MessageType.DOWNLOAD_REQUEST);
            this.filename = filename;
            this.offset = offset;
            this.length = length;
        }

        public String getFilename() {
            return filename;
        }

        public long getOffset() {
            return offset;
        }

        public long getLength() {
            return length;
        }

        @Override
        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(type.getCode());
            dos.writeLong(timestamp);
            dos.writeUTF(messageId);
            dos.writeUTF(filename);
            dos.writeLong(offset);
            dos.writeLong(length);

            return baos.toByteArray();
        }

        public static DownloadRequest deserializeFrom(ByteBuffer buffer) throws IOException {
            long timestamp = buffer.getLong();
            String messageId = readString(buffer);
            String filename = readString(buffer);
            long offset = buffer.getLong();
            long length = buffer.getLong();

            return new DownloadRequest(filename, offset, length);
        }
    }

    // Download response message
    public static class DownloadResponse extends Message {
        private final ResponseCode responseCode;
        private final long fileSize;
        private final byte[] data;
        private final byte[] checksum;

        public DownloadResponse(ResponseCode responseCode, long fileSize, byte[] data, byte[] checksum) {
            super(MessageType.DOWNLOAD_RESPONSE);
            this.responseCode = responseCode;
            this.fileSize = fileSize;
            this.data = data;
            this.checksum = checksum;
        }

        public ResponseCode getResponseCode() {
            return responseCode;
        }

        public long getFileSize() {
            return fileSize;
        }

        public byte[] getData() {
            return data != null ? data.clone() : null;
        }

        public byte[] getChecksum() {
            return checksum != null ? checksum.clone() : null;
        }

        @Override
        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(type.getCode());
            dos.writeLong(timestamp);
            dos.writeUTF(messageId);
            dos.writeByte(responseCode.getCode());
            dos.writeLong(fileSize);

            if (data != null) {
                dos.writeInt(data.length);
                dos.write(data);
            } else {
                dos.writeInt(0);
            }

            if (checksum != null) {
                dos.writeInt(checksum.length);
                dos.write(checksum);
            } else {
                dos.writeInt(0);
            }

            return baos.toByteArray();
        }

        public static DownloadResponse deserializeFrom(ByteBuffer buffer) throws IOException {
            long timestamp = buffer.getLong();
            String messageId = readString(buffer);
            ResponseCode code = ResponseCode.fromCode(buffer.get());
            long fileSize = buffer.getLong();

            int dataLength = buffer.getInt();
            byte[] data = null;
            if (dataLength > 0) {
                data = new byte[dataLength];
                buffer.get(data);
            }

            int checksumLength = buffer.getInt();
            byte[] checksum = null;
            if (checksumLength > 0) {
                checksum = new byte[checksumLength];
                buffer.get(checksum);
            }

            return new DownloadResponse(code, fileSize, data, checksum);
        }
    }

    // Error message
    public static class ErrorMessage extends Message {
        private final ResponseCode errorCode;
        private final String errorMessage;
        private final String details;

        public ErrorMessage(ResponseCode errorCode, String errorMessage, String details) {
            super(MessageType.ERROR);
            this.errorCode = errorCode;
            this.errorMessage = errorMessage;
            this.details = details;
        }

        public ResponseCode getErrorCode() {
            return errorCode;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public String getDetails() {
            return details;
        }

        @Override
        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(type.getCode());
            dos.writeLong(timestamp);
            dos.writeUTF(messageId);
            dos.writeByte(errorCode.getCode());
            dos.writeUTF(errorMessage);
            dos.writeUTF(details != null ? details : "");

            return baos.toByteArray();
        }

        public static ErrorMessage deserializeFrom(ByteBuffer buffer) throws IOException {
            long timestamp = buffer.getLong();
            String messageId = readString(buffer);
            ResponseCode code = ResponseCode.fromCode(buffer.get());
            String errorMessage = readString(buffer);
            String details = readString(buffer);

            return new ErrorMessage(code, errorMessage, details.isEmpty() ? null : details);
        }
    }

    // Helper method to read strings from ByteBuffer
    private static String readString(ByteBuffer buffer) throws IOException {
        int length = buffer.getShort() & 0xFFFF;
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, "UTF-8");
    }

    // Message framing for network transmission
    public static class Frame {
        private static final byte[] MAGIC = new byte[] { 0x46, 0x53, 0x52, 0x56 }; // "FSRV"

        public static byte[] frame(byte[] data) {
            ByteBuffer buffer = ByteBuffer.allocate(MAGIC.length + 4 + 4 + data.length);
            buffer.put(MAGIC);
            buffer.putInt(PROTOCOL_VERSION);
            buffer.putInt(data.length);
            buffer.put(data);
            return buffer.array();
        }

        public static byte[] unframe(byte[] frame) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(frame);

            // Check magic bytes
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("Invalid frame magic");
            }

            // Check protocol version
            int version = buffer.getInt();
            if (version != PROTOCOL_VERSION) {
                throw new IOException("Unsupported protocol version: " + version);
            }

            // Read data
            int dataLength = buffer.getInt();
            byte[] data = new byte[dataLength];
            buffer.get(data);

            return data;
        }
    }
}