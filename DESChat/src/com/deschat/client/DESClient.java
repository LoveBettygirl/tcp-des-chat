package com.deschat.client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;

import com.deschat.des.Base64Tool;
import com.deschat.des.DES;
import com.deschat.server.DESServer;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JSeparator;
import javax.swing.Box;
import javax.swing.border.TitledBorder;
import java.awt.GridLayout;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JButton;
import java.awt.Color;
import javax.swing.BoxLayout;
import net.miginfocom.swing.MigLayout;
import java.awt.Toolkit;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.net.*;
import java.util.Arrays;
import java.io.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class DESClient extends JFrame {

	private JPanel contentPane;
	
	private JPanel panel1;
	private JPanel panel2;
	private JPanel panel3;
	
	private JScrollPane scrollPane;
	private JScrollPane scrollPane_1;
	
	private JTextArea workLog;
	private JTextArea editMsg;
	
	private JLabel clientIPLabel;
	private JLabel clientPortLabel;
	private JLabel priKeyLabel;
	private JLabel lblNewLabel;
	private JLabel serverIPLabel;
	
	private JButton sendMsg;
	
	/** 是否退出主线程，true为退出 */
	public volatile boolean exit = false; 
	
	/** 客户端与服务器交互的线程 */
	private ClientThread client;
	
	/**
	 * 客户端线程类
	 * @author user
	 */
	private class ClientThread extends Thread {
		private Socket socket;
		private int port;
		private InetAddress address;
		private String serverIP;
		private String key;
		private volatile boolean getKey=false;
		public ClientThread(Socket s,String serverIP) {
			socket=s;
			port=socket.getLocalPort();
			address=socket.getInetAddress();
			this.serverIP=serverIP;
			start();
		}
		
		@Override
		public void run() {
			InputStream in=null;
			OutputStream out=null;
			InputStreamReader ir = null;
            BufferedReader br = null;
			while(true) {
				try {
					in = socket.getInputStream();//获取TCP连接的输入字节流
					out = socket.getOutputStream();
					//聊天前首先接收服务器发来的密钥
					if(!getKey) {
						StringBuilder receiveKey=new StringBuilder();
						int charcount=0;
						//逐字节解析密钥
						for (int c = in.read(); c!=-1; c = in.read()) {
			                receiveKey.append((char)c);
			                charcount++;
			                if(charcount==8) { //服务器发来的前8个字节是密钥
			                	break;
			                }
			            }
						key=receiveKey.toString();
		                getKey=true;
		                updateInfo();
					}
					DES des=new DES(key);
	                String receiveMsg=null;
	                ir = new InputStreamReader(in);//将TCP字节流转为字符流
	                br = new BufferedReader(ir);//带缓冲区的文本读取
	                //接收消息并解密，不同消息的边界为换行符
	                while ((receiveMsg = br.readLine()) != null) {
	                	if(receiveMsg.equals("END")) break;
	                	System.out.println("Decry binary source: "+receiveMsg);
	                	String res=des.getResult(receiveMsg, false);//DES解密
	                	System.out.println("Decry result: "+res);
	                    rcvLog(res);//将解密后的消息输出到对话框
	                }
	                //关闭连接的输入流和输出流
	                socket.shutdownInput();
	                socket.shutdownOutput();
				}
				catch(IOException e) {
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
				}
				finally {
					try {
						//关闭流和套接字
						if(br!=null) {
		                	br.close();
		                }
		                if(ir!=null) {
		                	ir.close();
		                }
		                if(in!=null) {
		                	in.close();
		                }
		                if(out!=null) {
		                	out.close();
		                }
		                if(socket!=null) {
		                	if(!socket.isClosed()) {
		                		socket.close();
		                	}
		                }
					}
					catch(IOException e1) {
						e1.printStackTrace();
						System.out.println("IOException: "+e1.getMessage());
					}
					finally {
						if(exit) {
							System.exit(0);
						}
						else {
							//断线重连，隔一秒尝试连接一次
							//重新连接成功以后会重新获得密钥
							reconnecting();
							try {
								Thread.sleep(1000);
							} catch (InterruptedException e) {
								// TODO 自动生成的 catch 块
								e.printStackTrace();
								System.out.println("InterruptedException: "+e.getMessage());
							}
							try {
								//重新建立套接字并和服务器连接，保持客户端原端口不变
								socket=new Socket(serverIP,2000,address,port);
								socket.setSoTimeout(0);//设置读取超时为0
								getKey=false;
							} catch (IOException e) {
								// TODO 自动生成的 catch 块
								e.printStackTrace();
								System.out.println("IOException: "+e.getMessage());
							}
						}
					}
				}
			}
		}
		
		public Socket getSocket() {
			return socket;
		}
		
		public String getDESKey() {
			return key;
		}
		
		private void updateInfo() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					sendMsg.setEnabled(true);
					clientIPLabel.setText("IP："+address.toString().substring(1));
					clientPortLabel.setText("端口号："+port);
					serverIPLabel.setText("服务器IP："+address.toString().substring(1));
					priKeyLabel.setText("密钥："+key);
					workLog.append("Connect Success!\nGot key: "+key+"\nBegin to chat...\n");
				}
			});
		}
		
		private void rcvLog(String msg) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("server -> client: \n"+msg+"\n");
				}
			});
		}
		
		private void reconnecting() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Connect failed!\nReconnecting...\n");
					sendMsg.setEnabled(false);
				}
			});
		}
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					DESClient frame = new DESClient();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	private void setSkin() {
		try {
			BeautyEyeLNFHelper.frameBorderStyle = BeautyEyeLNFHelper.FrameBorderStyle.osLookAndFeelDecorated;
			BeautyEyeLNFHelper.launchBeautyEyeLNF();
			UIManager.put("RootPane.setupButtonVisible", false);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public DESClient(Socket s,String serverIP) {
		this();
		client=new ClientThread(s,serverIP);
	}
	
	/**
	 * Create the frame.
	 */
	public DESClient() {
		setSkin();
		setIconImage(Toolkit.getDefaultToolkit().getImage(this.getClass().getResource("/img/smile.png")));
		setResizable(false);
		setTitle("DESClient");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 706, 429);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		panel1 = new JPanel();
		panel1.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "客户端工作日志", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		panel1.setBounds(10, 10, 330, 368);
		contentPane.add(panel1);
		panel1.setLayout(new MigLayout("", "[318px]", "[330px]"));
		
		scrollPane = new JScrollPane();
		panel1.add(scrollPane, "cell 0 0,grow");
		
		workLog = new JTextArea();
		workLog.setEditable(false);
		scrollPane.setViewportView(workLog);
		
		panel2 = new JPanel();
		panel2.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "客户端信息", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		panel2.setBounds(361, 10, 318, 132);
		contentPane.add(panel2);
		panel2.setLayout(new MigLayout("", "[96px]", "[29px][29px][29px]"));
		
		clientIPLabel = new JLabel("IP：");
		panel2.add(clientIPLabel, "cell 0 0,alignx left,aligny center");
		
		clientPortLabel = new JLabel("端口号：");
		panel2.add(clientPortLabel, "cell 0 1,alignx left,aligny center");
		
		priKeyLabel = new JLabel("密钥：");
		panel2.add(priKeyLabel, "cell 0 2,alignx left,aligny center");
		
		panel3 = new JPanel();
		panel3.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "向服务器发送消息", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		panel3.setBounds(361, 151, 318, 227);
		contentPane.add(panel3);
		panel3.setLayout(new MigLayout("", "[168px][33px][91px]", "[29px][140px][37px]"));
		
		lblNewLabel = new JLabel("编辑消息内容：");
		panel3.add(lblNewLabel, "cell 0 0,alignx left,aligny top");
		
		scrollPane_1 = new JScrollPane();
		panel3.add(scrollPane_1, "cell 0 1 3 1,grow");
		
		editMsg = new JTextArea();
		scrollPane_1.setViewportView(editMsg);
		
		serverIPLabel = new JLabel("服务器IP：");
		panel3.add(serverIPLabel, "cell 0 2,alignx left,aligny center");
		
		sendMsg = new JButton("发送");
		sendMsg.setEnabled(false);
		sendMsg.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if(editMsg.getText().length()==0) {
					JOptionPane.showMessageDialog(null, "消息内容不能为空！","Warning",JOptionPane.WARNING_MESSAGE);
					return;
				}
				Socket s=client.getSocket();
				try {
					OutputStream out;
					String temp,response;
					DES des=new DES(client.getDESKey());
					out = s.getOutputStream();//获取TCP连接的输出字节流
					response=editMsg.getText().trim();//从输入框获取要发送的原文
					System.out.println("Encry source: "+response);
	                temp=des.getResult(response, true);//DES加密
	                System.out.println("Encry binary result: "+temp);
	                temp+="\n";//消息边界为换行符（不需要加密），不加边界会一直阻塞
	                out.write(temp.getBytes());//以字节形式发送加密后的消息
		            out.flush();//清空缓冲区数据
		            workLog.append("client -> server: \n"+response+"\n");
					editMsg.setText("");//发送后清空输入框
				}
				catch(IOException e) {
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
				}
			}
		});
		panel3.add(sendMsg, "cell 2 2,growx,aligny top");
		
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				editMsg.requestFocus();
			}
			
			@Override
		    public void windowClosing(WindowEvent e) {				
				exit=true;
				Socket s=client.getSocket();
				//客户端终止与服务器通信的方式是点击窗口的×并向服务器发送END结束符，释放资源，退出线程
				try {
					OutputStream out;
					out = s.getOutputStream();
					String temp="END";
	                temp+="\n";
	                out.write(temp.getBytes());
		            out.flush();//清空缓冲区数据
				}
				catch(IOException e1) {
					e1.printStackTrace();
					System.out.println("IOException: "+e1.getMessage());
				}
		    }
		});
	}
}
