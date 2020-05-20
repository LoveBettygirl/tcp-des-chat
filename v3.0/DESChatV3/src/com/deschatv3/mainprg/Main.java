package com.deschatv3.mainprg;

import java.awt.*;

import javax.swing.*;
import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;
import com.deschatv3.client.*;
import com.deschatv3.server.*;

import java.net.*;
import java.text.SimpleDateFormat;
import java.io.*;
import java.util.*;

public class Main {
	
	private static void setLogFile(String src) {
		Date date = new Date();
		SimpleDateFormat dateFormat= new SimpleDateFormat("yyyyMMddHHmmss");

		//���ô�����Ϊ�ļ��������쳣��ջ��Ϣ������ļ���
		PrintStream print;
		try {
			print = new PrintStream("error-"+src+"-"+dateFormat.format(date)+".log");
			System.setErr(print);
			/*print2 = new PrintStream("stdout-"+src+"-"+dateFormat.format(date)+".log");
			System.setOut(print2);*/
		} catch (FileNotFoundException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
			System.out.println("FileNotFoundException: "+e.getMessage());
		} 
	}

	public static void main(String[] args) {
		// TODO �Զ����ɵķ������
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
        if(option==0) { //�����ͻ����߳�
        	Main.setLogFile("client");
        	String serverIP = JOptionPane.showInputDialog(null, "Please input the server IP address:\n", "Client Login", JOptionPane.QUESTION_MESSAGE);
        	String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
        			+"(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
        	while(serverIP!=null&&!(serverIP.matches(regex))) { //�������ķ�����IP��ַ��ʽ�Ƿ�Ϸ�
        		JOptionPane.showMessageDialog(null, "Invaild IP address, please input again!","Invalid",JOptionPane.ERROR_MESSAGE);
        		serverIP=JOptionPane.showInputDialog(null, "Please input the server IP address:\n", "Client Login", JOptionPane.QUESTION_MESSAGE);
        	}
        	System.out.println(serverIP);
        	if(serverIP!=null) {
        		//�����׽��ֲ��ͷ���������
				DESClient clientDlg=new DESClient(serverIP,2000);//���ӳɹ������ͻ����̲߳��򿪶Ի���
				/*EventQueue.invokeLater(new Runnable() {
        			@Override
                    public void run() {
                        clientDlg.setVisible(true);
                    }
                });*/
        	}
        }
        else if(option==1) { //�����������߳�
        	Main.setLogFile("server");
        	DESServer serverDlg=new DESServer();//�򿪶Ի��򲢽��������߳�
        	EventQueue.invokeLater(new Runnable() {
        		@Override
                public void run() {
                	serverDlg.setVisible(true);
                }
            });
        }
	}

}
