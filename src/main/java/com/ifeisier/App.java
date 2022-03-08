package com.ifeisier;

import org.apache.commons.cli.*;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;

/**
 * 应用程序入口
 *
 * @author ifeisier
 * @version 1.0
 */
public class App {
    public static void main(String[] args) {

        Result result = parseArg(args);
        if (result == null) {
            return;
        }

        Collection<File> srcFiles;
        String resultSrc = result.getSrc();
        File srcFile = new File(resultSrc);
        File destFile = new File(result.getDest());

        if (!srcFile.exists()) {
            System.out.println("源文件或文件夹不存在");
            return;
        }

        if (destFile.exists() && !destFile.isDirectory()) {
            System.out.println("目标文件必须是目录");
            return;
        }

        if (srcFile.isFile()) {
            srcFiles = Collections.singletonList(srcFile);
            resultSrc = null;
        } else {
            srcFiles = FileUtils.listFiles(srcFile, null, true);
            if (resultSrc.endsWith("\\") || resultSrc.endsWith("/")) {
                resultSrc = resultSrc.substring(0, resultSrc.length() - 1);
            }
        }


        FileSecurity fileSecurity = null;
        try {
            fileSecurity = new FileSecurity(srcFiles, destFile, resultSrc, result.isEncrypt());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("加密/解密算法不存在");
            return;
        }

        try {
            fileSecurity.run();
        } catch (FileNotFoundException e) {
            System.out.println("文件不存在1");
        } catch (Exception e) {
            System.out.println("文件不存在2");
        }
    }

    private static Result parseArg(final String[] args) {
        Options options = new Options();
        options.addOption(Option.builder("e").longOpt("encrypt").desc("加密文件").build());
        options.addOption(Option.builder("d").longOpt("decrypt").desc("解密文件").build());
        options.addOption(Option.builder("src").longOpt("source").desc("源文件路径或指定文件").hasArg(true).argName("file path").type(String.class).numberOfArgs(1).build());
        options.addOption(Option.builder("dest").longOpt("destination").desc("目标目录").hasArg(true).argName("file path").type(String.class).numberOfArgs(1).build());
        options.addOption(new Option("v", "version", false, "软件版本"));
        options.addOption(new Option("h", "help", false, "帮助信息"));

        HelpFormatter hf = new HelpFormatter();
        if (args.length == 0) {
            hf.printHelp("FileSecurity", options, true);
            return null;
        }

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = null;
        try {
            commandLine = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("不接受这个参数");
            return null;
        }

        boolean isEncrypt = true;
        String src = null;
        String dest = null;
        if (commandLine.hasOption('h')) {
            hf.printHelp("FileSecurity", options, true);
            return null;
        } else if (commandLine.hasOption('v')) {
            System.out.println("程序版本 " + FileSecurity.MAIN_VERSION + "." + FileSecurity.MINOR_VERSION);
            return null;
        }

        if (commandLine.hasOption('d')) {
            isEncrypt = false;
        }
        if (commandLine.hasOption("src")) {
            src = commandLine.getOptionValue("src");
        }
        if (commandLine.hasOption("dest")) {
            dest = commandLine.getOptionValue("dest");
        }

        if (src == null) {
            System.out.println("没有指定源文件路径");
            return null;
        } else if (dest == null) {
            System.out.println("没有指定目标文件路径");
            return null;
        }

        return new Result(src, dest, isEncrypt);
    }

    private static class Result {
        private final String src;
        private final String dest;
        private final boolean isEncrypt;

        public Result(String src, String dest, boolean isEncrypt) {
            this.src = src;
            this.dest = dest;
            this.isEncrypt = isEncrypt;
        }

        public String getSrc() {
            return src;
        }

        public String getDest() {
            return dest;
        }

        public boolean isEncrypt() {
            return isEncrypt;
        }
    }
}
