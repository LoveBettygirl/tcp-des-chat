package com.deschatv2.mainprg;

import java.awt.*;

import javax.swing.*;
import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;
import com.deschatv2.client.*;
import com.deschatv2.server.*;

import java.net.*;
import java.text.SimpleDateFormat;
import java.io.*;
import java.util.*;

public class Main {
	
	private static void setLogFile(String src) {
		Date date = new Date();
		SimpleDateFormat dateFormat= new SimpleDateFormat("yyyyMMddHHmmss");

		//设置错误流为文件流，将异常堆栈信息输出到文件中
		PrintStream print;
		try {
			print = new PrintStream("error-"+src+"-"+dateFormat.format(date)+".log");
			System.setErr(print);
			/*print2 = new PrintStream("stdout-"+src+"-"+dateFormat.format(date)+".log");
			System.setOut(print2);*/
		} catch (FileNotFoundException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
			System.out.println("FileNotFoundException: "+e.getMessage());
		} 
	}

	public static void main(String[] args) {
		// TODO 自动生成的方法存根
		try {
			BeautyEyeLNFHelper.frameBorderStyle = BeautyEyeLNFHelper.FrameBorderStyle.osLookAndFeelDecorated;
			BeautyEyeLNFHelper.launchBeautyEyeLNF();
			UIManager.put("RootPane.setupButtonVisible", false);
		}
		catch(Exception e) {
			e.printStackTrace();
		} 
		Object[] options = {"Client","Server"};
		int option=JOptionPane.showOptionDialog(null,"Client or Server?","Login",
                JOptionPane.YES_NO_OPTION,JOptionPane.QUESTION_MESSAGE,null,options,options[0]);
		System.out.println("Choose: "+option);
        if(option==0) { //建立客户端线程
        	Main.setLogFile("client");
        	String serverIP = JOptionPane.showInputDialog(null, "Please input the server IP address:\n", "Client Login", JOptionPane.QUESTION_MESSAGE);
        	String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
        	while(serverIP!=null&&!(serverIP.matches(regex))) { //检查输入的服务器IP地址格式是否合法
        		JOptionPane.showMessageDialog(null, "Invaild IP address, please input again!","Invalid",JOptionPane.ERROR_MESSAGE);
        		serverIP=JOptionPane.showInputDialog(null, "Please input the server IP address:\n", "Client Login", JOptionPane.QUESTION_MESSAGE);
        	}
        	System.out.println(serverIP);
        	if(serverIP!=null) {
        		try {
        			//建立套接字并和服务器连接
					Socket s=new Socket(serverIP,2000);//随机分配空闲端口号
					s.setSoTimeout(0);//设置读取超时为0
					DESClient clientDlg=new DESClient(s,serverIP);//连接成功后建立客户端线程并打开对话框
					EventQueue.invokeLater(new Runnable() {
	        			@Override
	                    public void run() {
	                        clientDlg.setVisible(true);
	                    }
	                });
				} catch (UnknownHostException e) {
					// TODO 自动生成的 catch 块
					e.printStackTrace();
					System.out.println("UnknownHostException: "+e.getMessage());
					JOptionPane.showMessageDialog(null, "UnknownHostException: "+e.getMessage(),"Error",JOptionPane.ERROR_MESSAGE);
				} catch (IOException e) {
					// TODO 自动生成的 catch 块
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
					JOptionPane.showMessageDialog(null, "IOException: "+e.getMessage(),"Error",JOptionPane.ERROR_MESSAGE);
				}
        	}
        }
        else if(option==1) { //建立服务器线程
        	Main.setLogFile("server");
        	DESServer serverDlg=new DESServer();//打开对话框并建立监听线程
        	EventQueue.invokeLater(new Runnable() {
        		@Override
                public void run() {
                	serverDlg.setVisible(true);
                }
            });
        }
	}

}
