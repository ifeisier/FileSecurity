package com.ifeisier;

import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 文件加密解密类
 * <p>
 * 数据格式：
 * MAGIC（八字节） + MAIN_VERSION（两字节） + MINOR_VERSION（两字节） + 密码（32字节）+ VI（12字节）+ 分段数量（4字节）+ 每段加密后的长度（4字节）... + 加密后的文件
 *
 * @author ifeisier
 * @since 1.0
 */
public class FileSecurity {
    // 这个是加密后文件的最开始字符，表名这是我的程序加密的
    private final static byte[] MAGIC = {0x69, 0x66, 0x65, 0x69, 0x73, 0x69, 0x65, 0x72};

    // 主版本
    public final static short MAIN_VERSION = 1;

    // 次版本
    public final static short MINOR_VERSION = 0;

    // 分段长度单位(Byte)
    private static final int SEGMENT_LENGTH = 33554432;
    // 分段长度数据所占用的字节数
    private static final int SEGMENT_LENGTH_BYTE = 4;

    // 线程池大小
    private static final int THREAD_POOL_SIZE = 4; // 4 * 4

    // 协议头基础偏移
    private static final long PROTOCOL_HEADER_BASICS_OFFSET = 60;


    // AES 256 GCM
    private SecretKey key;
    private final byte[] IV = new byte[12];

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Collection<File> srcFile;
    private final File destFile;
    private final boolean isEncrypt;
    private final ExecutorService[] executorService = new ExecutorService[THREAD_POOL_SIZE];
    private final List<Map<String, Object>> randomAccessFiles = new ArrayList<>();
    private final String rootPath;

    /**
     * FileSecurity 构造方法
     *
     * @param srcFile   源文件
     * @param destFile  目标文件
     * @param rootPath  如果目录，则表示根路径
     * @param isEncrypt true 加密，false 解密
     * @since 1.0
     */
    public FileSecurity(Collection<File> srcFile, File destFile, String rootPath, boolean isEncrypt) throws NoSuchAlgorithmException {
        this.srcFile = srcFile;
        this.destFile = destFile;
        this.rootPath = rootPath;
        this.isEncrypt = isEncrypt;
        for (int i = 0; i < THREAD_POOL_SIZE; i++) {
            this.executorService[i] = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        }

        // 生成指定大小的对称加密秘钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        this.key = keyGenerator.generateKey();

        // 获取指定长度的随机数，可以认为是偏移
        SecureRandom random = new SecureRandom();
        random.nextBytes(this.IV);
    }

    /**
     * 执行加密或解密
     *
     * @since 1.0
     */
    public void run() throws Exception {
        for (File srcFile : this.srcFile) {
            String destPath = destFile.getPath();
            String srcFileName = "";

            // 指定的是一个具体文件
            if (this.rootPath == null) {
                srcFileName += File.separatorChar + srcFile.getName();
            } else {
                srcFileName = srcFile.getPath().replace(this.rootPath, "");
            }

            if (this.isEncrypt) {
                destPath += srcFileName + ".ifeisier";
            } else {
                if (srcFileName.endsWith(".ifeisier")) {
                    destPath += srcFileName.substring(0, srcFileName.length() - 9);
                }
            }

            File destFile = new File(destPath);

            FileUtils.createParentDirectories(destFile);

            RandomAccessFile srcRas = new RandomAccessFile(srcFile, "r");
            RandomAccessFile destRas = new RandomAccessFile(destFile, "rw");

            int[] segmentLength = encryptAndDecryptCore(srcRas, destRas, srcFile.length());
            Map<String, Object> map = new HashMap<>();
            map.put("srcRas", srcRas);
            map.put("destRas", destRas);
            map.put("segmentLength", segmentLength);
            randomAccessFiles.add(map);
        }

        for (int i = 0; i < THREAD_POOL_SIZE; i++) {
            this.executorService[i].shutdown();
        }

        try {
            for (int i = 0; i < THREAD_POOL_SIZE; i++) {
                this.executorService[i].awaitTermination(Integer.MAX_VALUE, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        for (Map<String, Object> randomAccessFile : randomAccessFiles) {
            if (this.isEncrypt) {
                this.addFileHeader((RandomAccessFile) randomAccessFile.get("destRas"),
                        (int[]) randomAccessFile.get("segmentLength"));
            }

            ((RandomAccessFile) randomAccessFile.get("srcRas")).close();
            ((RandomAccessFile) randomAccessFile.get("destRas")).close();
        }

        System.out.println("结束时间：" + LocalDateTime.now(ZoneOffset.of("+8")).format(FileSecurity.DATE_FORMATTER));
    }

    /**
     * 加密和解密的核心方法，该方法主要负责拆分任务，将任务提交到线程
     *
     * @param srcRas  源文件
     * @param destRas 目标文件
     * @param length  源文件长度
     * @return 返回每个字段的长度
     * @throws Exception 有异常抛出
     * @since 1.0
     */
    private int[] encryptAndDecryptCore(final RandomAccessFile srcRas, final RandomAccessFile destRas, long length) throws Exception {
        // 计算任务数
        long task = length / FileSecurity.SEGMENT_LENGTH;
        if (this.isEncrypt) {
            if (length % FileSecurity.SEGMENT_LENGTH != 0) {
                task = task + 1;
            }
        } else {
            task = securityCheck(srcRas);
        }

        int segmentLengthTemp;
        long srcFileOffset = FileSecurity.PROTOCOL_HEADER_BASICS_OFFSET;
        long offset = FileSecurity.PROTOCOL_HEADER_BASICS_OFFSET + (task * FileSecurity.SEGMENT_LENGTH_BYTE);
        int[] segment = new int[(int) task];

        for (int i = 0; i < task; i++) {
            if (this.isEncrypt) {
                this.executorService[i % FileSecurity.THREAD_POOL_SIZE].execute(new Task(offset, i, FileSecurity.SEGMENT_LENGTH, segment, true, srcRas, destRas));
                offset = offset + FileSecurity.SEGMENT_LENGTH;
            } else {
                synchronized (srcRas) {
                    srcRas.seek(FileSecurity.PROTOCOL_HEADER_BASICS_OFFSET);
                    segmentLengthTemp = srcRas.readInt();
                    this.executorService[i % FileSecurity.THREAD_POOL_SIZE].execute(new Task(offset, i, segmentLengthTemp, segment, false, srcRas, destRas));
                    srcFileOffset = srcFileOffset + FileSecurity.SEGMENT_LENGTH_BYTE;
                    offset = offset + segmentLengthTemp;
                }
            }
        }

        return segment;
    }

    /**
     * 文件加密时，添加文件头
     *
     * @param destRas 目标文件
     * @param segment 每段长度
     * @throws IOException 文件操作异常
     * @since 1.0
     */
    private void addFileHeader(RandomAccessFile destRas, final int[] segment) throws IOException {
        destRas.seek(0);

        destRas.write(FileSecurity.MAGIC);
        destRas.writeShort(FileSecurity.MAIN_VERSION);
        destRas.writeShort(FileSecurity.MINOR_VERSION);

        destRas.write(this.key.getEncoded());
        destRas.write(this.IV);

        destRas.writeInt(segment.length);
        for (int s : segment) {
            destRas.writeInt(s);
        }
    }

    /**
     * 在解密时，会检查是不是使用本软件加密的，加密版本，获取 KEY 和 IV
     *
     * @param srcRas 要检查的源文件
     * @return 返回分段数量
     * @throws Exception 抛出具体异常信息
     * @since 1.0
     */
    private int securityCheck(final RandomAccessFile srcRas) throws Exception {
        srcRas.seek(0);
        byte[] b = new byte[MAGIC.length];
        srcRas.read(b);
        if (!Arrays.equals(FileSecurity.MAGIC, b)) {
            throw new Exception("不是" + new String(FileSecurity.MAGIC) + "加密的");
        }

        int ver = srcRas.readShort();
        if (ver != FileSecurity.MAIN_VERSION) {
            throw new Exception("版本不一致");
        }
        ver = srcRas.readShort();
        if (ver != FileSecurity.MINOR_VERSION) {
            throw new Exception("版本不一致");
        }

        b = new byte[32];
        srcRas.read(b);
        this.key = new SecretKeySpec(b, "AES");
        srcRas.read(this.IV);

        return srcRas.readInt();
    }

    /**
     * 加密数据
     *
     * @param plaintext 要加密内容
     * @param key       密钥
     * @param IV        偏移
     * @return 加密后的数据
     * @throws Exception 异常后抛出
     * @since 1.0
     */
    private byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {
        // 加密和解密由 Cipher 类处理
        // 算法/模式/补码方式
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
        // 初始化 Cipher 加密或解密
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * 解密数据
     *
     * @param cipherText 要解密的内容
     * @param key        密钥
     * @param IV         偏移
     * @return 解密后的文本
     * @throws Exception 异常后抛出
     * @since 1.0
     */
    private byte[] decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        return cipher.doFinal(cipherText);
    }

    /**
     * 任务类
     *
     * @since 1.0
     */
    private class Task implements Runnable {
        private long offset;
        private final int taskID;
        private final int segmentLength;
        private final int[] segment;
        private final boolean isEncrypt;
        private final RandomAccessFile srcRas;
        private final RandomAccessFile destRas;

        /**
         * Task 构造方法
         *
         * @param offset        偏移，根据 isEncrypt 的值，有不同的作用
         * @param taskID        任务ID
         * @param segmentLength 从源文件中读取的分段数据长度
         * @param segment       记录每个分段加密后的数据长度
         * @param isEncrypt     true：加密，false：解密
         * @param srcRas        源文件
         * @param destRas       目标文件
         * @since 1.0
         */
        public Task(long offset, int taskID, int segmentLength, int[] segment, boolean isEncrypt, RandomAccessFile srcRas, RandomAccessFile destRas) {
            this.offset = offset;
            this.taskID = taskID;
            this.segmentLength = segmentLength;
            this.segment = segment;
            this.isEncrypt = isEncrypt;
            this.srcRas = srcRas;
            this.destRas = destRas;
        }

        @Override
        public void run() {
            byte[] plaintext = new byte[this.segmentLength];
            try {
                int len = 0;
                long srcOffsetTemp;
                synchronized (srcRas) {
                    if (this.isEncrypt) {
                        // 文件加密从文件头开始读取
                        srcOffsetTemp = (long) this.taskID * FileSecurity.SEGMENT_LENGTH;
                        System.out.println("时间:" + LocalDateTime.now(ZoneOffset.of("+8")).format(FileSecurity.DATE_FORMATTER) + ", 加密任务:" + this.taskID + ", 偏移:" + srcOffsetTemp + ", 开始");
                    } else {
                        srcOffsetTemp = this.offset;
                        System.out.println("时间:" + LocalDateTime.now(ZoneOffset.of("+8")).format(FileSecurity.DATE_FORMATTER) + ", 解密任务:" + this.taskID + ", 偏移:" + srcOffsetTemp + ", 开始");
                    }
                    this.srcRas.seek(srcOffsetTemp);
                    len = srcRas.read(plaintext);
                    if (len < plaintext.length) {
                        byte[] temp = new byte[len];
                        System.arraycopy(plaintext, 0, temp, 0, len);
                        plaintext = temp;
                    }
                }

                byte[] context;
                if (this.isEncrypt) {
                    context = FileSecurity.this.encrypt(plaintext, FileSecurity.this.key, FileSecurity.this.IV);

                    // 重新计算偏移量，因为加密后的长度和读取的长度不一样
                    this.offset += ((long) (context.length - len) * this.taskID);
                } else {
                    context = FileSecurity.this.decrypt(plaintext, FileSecurity.this.key, FileSecurity.this.IV);
                    this.offset = (long) this.taskID * FileSecurity.SEGMENT_LENGTH;
                }

                synchronized (srcRas) {
                    this.segment[this.taskID] = context.length;
                    this.destRas.seek(this.offset);
                    this.destRas.write(context, 0, context.length);
                }

                if (this.isEncrypt) {
                    System.out.println("时间:" + LocalDateTime.now(ZoneOffset.of("+8")).format(FileSecurity.DATE_FORMATTER) + ", 加密任务:" + this.taskID + ", 偏移:" + srcOffsetTemp + ", 结束");
                } else {
                    System.out.println("时间:" + LocalDateTime.now(ZoneOffset.of("+8")).format(FileSecurity.DATE_FORMATTER) + ", 解密任务:" + this.taskID + ", 偏移:" + srcOffsetTemp + ", 结束");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }
}
