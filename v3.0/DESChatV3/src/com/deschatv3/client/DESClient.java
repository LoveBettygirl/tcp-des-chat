package com.deschatv3.client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;

import com.deschatv3.alg.*;
import com.deschatv3.server.DESServer;

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
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.io.*;
import java.nio.*;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.math.BigInteger;
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
	
	/** 客户端与服务器交互的句柄 */
	private AsyncClientHandler clientHandle;
	
	private class ClientWriteHandler implements CompletionHandler<Integer, ByteBuffer>{
		private AsynchronousSocketChannel clientChannel;
		private CountDownLatch latch;
		public ClientWriteHandler(AsynchronousSocketChannel clientChannel,CountDownLatch latch) {
			this.clientChannel = clientChannel;
			this.latch = latch;
		}
		@Override
		public void completed(Integer result, ByteBuffer buffer) {
			//完成全部数据的写入
			if (buffer.hasRemaining()) {
				clientChannel.write(buffer, buffer, this);
			}
		}
		@Override
		public void failed(Throwable exc, ByteBuffer attachment) {
			exc.printStackTrace();
			System.out.println("Data send failed: "+exc.getMessage());
			try {
				clientChannel.close();
				latch.countDown();
			} catch (IOException e) {
			}
		}
	}

	private class ClientReadHandler implements CompletionHandler<Integer, ByteBuffer> {
		private AsynchronousSocketChannel clientChannel;
		private CountDownLatch latch;
		public ClientReadHandler(AsynchronousSocketChannel clientChannel,CountDownLatch latch) {
			this.clientChannel = clientChannel;
			this.latch = latch;
		}
		@Override
		public void completed(Integer result,ByteBuffer buffer) {
			buffer.flip();
			byte[] bytes = new byte[buffer.remaining()];
			buffer.get(bytes);
			String body;
			try {
				body = new String(bytes,"UTF-8");
				if (!clientHandle.geteofRSAPublicKey) {
					clientHandle.rcvingRSAPublicKey();
					clientHandle.geteofRSAPublicKey = true;
					clientHandle.e_ = body;
					ByteBuffer readBuffer = ByteBuffer.allocate(1024);
					clientChannel.read(readBuffer,readBuffer,new ClientReadHandler(clientChannel, latch));
				}
				else if (!clientHandle.getnofRSAPublicKey) {
					clientHandle.n_ = body;
					RSAPublicKey publicKey = new RSAPublicKey(new BigInteger(clientHandle.e_), new BigInteger(clientHandle.n_));
                	String encode = RSA.encry(clientHandle.key, publicKey);
                	System.out.println("e of RSA public key: "+clientHandle.e_);
                	System.out.println("n of RSA public key: "+clientHandle.n_);
                	System.out.println("RSA encrypt result: "+encode);
                	clientHandle.getnofRSAPublicKey = true;
                	clientHandle.sendMsg(encode);
                	clientHandle.gotRSAPublicKey();
                	clientHandle.beginToChat();
                	ByteBuffer readBuffer = ByteBuffer.allocate(1024);
    				clientChannel.read(readBuffer,readBuffer,new ClientReadHandler(clientChannel, latch));
				}
				else {
					if (exit) {
						latch.countDown();
						System.exit(0);
					}
					DES des=new DES(clientHandle.key);
	                String receiveMsg=body;
	                if(!receiveMsg.equals("END")) {
	                	//接收消息并解密
		                System.out.println("DES decry binary source: "+receiveMsg);
	                	String res=des.getResult(receiveMsg, false);//DES解密
	                	System.out.println("DES decry result: "+res);
	                	clientHandle.rcvLog(res);//将解密后的消息输出到对话框
	                	ByteBuffer readBuffer = ByteBuffer.allocate(1024);
						clientChannel.read(readBuffer,readBuffer,new ClientReadHandler(clientChannel, latch));
	                }
	                else {
	                	
	                }
				}
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			}
		}
		@Override
		public void failed(Throwable exc,ByteBuffer attachment) {
			exc.printStackTrace();
			System.out.println("Data receive failed: "+exc.getMessage());
			clientHandle.isconn = false;
			//断线重连，隔一秒尝试连接一次
			//重新连接成功以后会重新获得密钥
			clientHandle.reconnecting();
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
				System.out.println("InterruptedException: "+e.getMessage());
			}
			try {
				clientHandle.reconn = true;
				clientHandle.geteofRSAPublicKey=false;
				clientHandle.getnofRSAPublicKey=false;
				//重新建立套接字并和服务器连接，保持客户端原端口不变
				clientChannel.close();
				clientHandle.clientChannel = AsynchronousSocketChannel.open();
				clientHandle.clientChannel.bind(clientHandle.address);
				clientHandle.clientChannel.connect(new InetSocketAddress(clientHandle.serverIP, clientHandle.port), clientHandle, clientHandle);
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
				System.out.println("IOException: "+e.getMessage());
			}
		}
	}


	private class AsyncClientHandler implements CompletionHandler<Void, AsyncClientHandler>, Runnable{
		private AsynchronousSocketChannel clientChannel;
		private boolean reconn  = false;
		private boolean isconn = false;
		private String serverIP;
		private int port;
		private int localPort;
		private SocketAddress address;
		private String key;
		private String e_;
		private String n_;
		private volatile boolean geteofRSAPublicKey=false;
		private volatile boolean getnofRSAPublicKey=false;
		private CountDownLatch latch;
		public AsyncClientHandler(String serverIP, int port) {
			this.serverIP = serverIP;
			this.port = port;
			genRandomDESKey();
			try {
				//创建异步的客户端通道
				clientChannel = AsynchronousSocketChannel.open();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		@Override
		public void run() {
			//创建CountDownLatch等待
			latch = new CountDownLatch(1);
			Random r = new Random();
			int newPort = -1;
			//发起异步连接操作，回调参数就是这个类本身，如果连接成功会回调completed方法
			while(true) {
				try {
					newPort = r.nextInt(65536);
					clientChannel.bind(new InetSocketAddress("127.0.0.1", newPort));
				} catch (IOException e2) {
					// TODO 自动生成的 catch 块
					newPort = -1;
				}
				if (newPort != -1) {
					break;
				}
			}
			clientChannel.connect(new InetSocketAddress(serverIP, port), this, this);
			try {
				latch.await();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			try {
				clientChannel.close();
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (exit)
					System.exit(0);
			}
		}
		//连接服务器成功
		//意味着TCP三次握手完成
		@Override
		public void completed(Void result, AsyncClientHandler attachment) {
			isconn = true;
			try {
				address = clientChannel.getLocalAddress();
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			}
			updateInfo();
			EventQueue.invokeLater(new Runnable() {
    			@Override
                public void run() {
    				DESClient.this.setVisible(true);
                }
            });
			ByteBuffer readBuffer = ByteBuffer.allocate(1024);
			clientChannel.read(readBuffer,readBuffer,new ClientReadHandler(clientChannel, latch));
		}
		//连接服务器失败
		@Override
		public void failed(Throwable exc, AsyncClientHandler attachment) {
			exc.printStackTrace();
			if (!reconn) {
				System.out.println("Connect failed: "+exc.getMessage());
				JOptionPane.showMessageDialog(null, "Connect failed: "+exc.getMessage(),"Error",JOptionPane.ERROR_MESSAGE);
				try {
					clientChannel.close();
					latch.countDown();
				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					System.exit(0);
				}
			}
			else {
				//断线重连，隔一秒尝试连接一次
				//重新连接成功以后会重新获得RSA密钥
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					// TODO 自动生成的 catch 块
					e.printStackTrace();
					System.out.println("InterruptedException: "+e.getMessage());
				}
				try {
					clientHandle.reconn = true;
					clientHandle.geteofRSAPublicKey=false;
					clientHandle.getnofRSAPublicKey=false;
					//重新打开通道并和服务器连接，保持客户端原端口不变
					clientChannel.close();
					clientChannel = AsynchronousSocketChannel.open();
					clientChannel.bind(clientHandle.address);
					clientChannel.connect(new InetSocketAddress(serverIP, port), this, this);
				} catch (IOException e) {
					// TODO 自动生成的 catch 块
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
				}
			}
		}
		private void updateInfo() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					if (address instanceof InetSocketAddress) {
						localPort = ((InetSocketAddress)address).getPort();
						clientIPLabel.setText("IP："+((InetSocketAddress)address).getHostString());
					}
					clientPortLabel.setText("端口号："+localPort);
					serverIPLabel.setText("服务器IP："+serverIP);
					priKeyLabel.setText("DES密钥：保密");
					System.out.println("DES key: "+key);
					workLog.append("Connect Success!\nReady to receive RSA public key...\n");
				}
			});
		}
		
		public String getDESKey() {
			return key;
		}
		private void rcvingRSAPublicKey() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Receiving RSA public key from server...\n");
				}
			});
		}
		private void gotRSAPublicKey() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Get an RSA public key,\n");
					workLog.append("send RSA encrypted DES key to server...\n");
				}
			});
		}
		private void beginToChat() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					sendMsg.setEnabled(true);
					workLog.append("Begin to chat...\n");
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
					serverIPLabel.setText("未连接到服务器");
					workLog.append("Connect failed!\nReconnecting...\n");
					sendMsg.setEnabled(false);
				}
			});
		}
		//向服务器发送消息
		public void sendMsg(String msg){
			byte[] req = msg.getBytes();
			ByteBuffer writeBuffer = ByteBuffer.allocate(req.length);
			writeBuffer.put(req);
			writeBuffer.flip();
			//异步写
			clientChannel.write(writeBuffer, writeBuffer,new ClientWriteHandler(clientChannel, latch));
		}
		
		/**
		 * 生成随机DES密钥
		 */
		private void genRandomDESKey() {
			StringBuilder s=new StringBuilder();
			String alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
			Random r = new Random();
			for(int i=0;i<8;i++) {
				s.append(alpha.charAt(r.nextInt(26)));
			}
			key=s.toString();
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
	
	
	public DESClient(String serverIP, int port) {
		this();
		clientHandle = new AsyncClientHandler(serverIP, port);
		new Thread(clientHandle,"Client").start();
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
				String temp,response;
				DES des=new DES(clientHandle.getDESKey());
				response=editMsg.getText().trim();//从输入框获取要发送的原文
				System.out.println("DES encry source: "+response);
                temp=des.getResult(response, true);//DES加密
                System.out.println("DES encry binary result: "+temp);
                clientHandle.sendMsg(temp);
	            workLog.append("client -> server: \n"+response+"\n");
				editMsg.setText("");//发送后清空输入框
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
				if (clientHandle.isconn) {
					if (sendMsg.isEnabled()) {
						exit=true;
						clientHandle.sendMsg("END");
					}
				}
				else {
					exit=true;
					clientHandle.latch.countDown();
				}
		    }
		});
	}
}
