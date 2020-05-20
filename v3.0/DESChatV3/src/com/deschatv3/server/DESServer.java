package com.deschatv3.server;

import java.io.*;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import org.jb2011.lnf.beautyeye.BeautyEyeLNFHelper;

import com.deschatv3.alg.*;

import net.miginfocom.swing.MigLayout;
import javax.swing.JComboBox;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class DESServer extends JFrame {
	
	private JPanel subpanel1;
	private JPanel subpanel2;
	private JPanel subpanel3;
	
	private JScrollPane scrollPane;
	private JScrollPane scrollPane_1;
	
	private JTextArea workLog;
	private JTextArea editMsg;
	
	private JLabel serverIPLabel;
	private JLabel serverPortLabel;
	private JLabel lblNewLabel;
	private JLabel clientCountLabel;
	private JLabel maxclientLabel;
	
	private JButton sendMsg;
	
	private JComboBox clientListComboBox;

	private JPanel contentPane;
	
	/** 是否退出主线程，true为退出 */
	public volatile boolean exit = false; 
	
	/** 客户端列表 */
	private Map<String,Client> clients=new HashMap<String,Client>();
	
	/** 客户端数量 */
	private int count;
	
	/** 客户端编号 */
	private int index;
	
	private AsyncServerHandler serverHandle;
	
	private class Client {
		private String name;
		private AsynchronousSocketChannel channel;
		private SocketAddress address;
		private int port;
		public volatile boolean send=false;
		private volatile boolean makeRSAKey=false;
		private volatile boolean getDESKey=false;
		public volatile boolean prepare=true;
		private String key;
		private RSA rsa;
		private DES des;
		public Client(String name, AsynchronousSocketChannel channel) {
			this.name = name;
			this.channel = channel;
			try {
				address = channel.getRemoteAddress();
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			}
			if (address instanceof InetSocketAddress) {
				port = ((InetSocketAddress)address).getPort();
			}
		}
		private void prepare() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					if (prepare) {
						if (name.equals((String)clientListComboBox.getSelectedItem())) {
							sendMsg.setEnabled(false);
						}
					}
				}
			});
		}
		
		private void prepareDone() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					if (name.equals((String)clientListComboBox.getSelectedItem())) {
						sendMsg.setEnabled(true);
					}
					prepare = false;
				}
			});
		}
		
		private void genRSAPublicKey() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Generating RSA public key for "+name+"...\n");
				}
			});
		}
		
		private void sendRSAPublicKey() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Send RSA public key to "+name+"...\n");
				}
			});
		}
		
		private void rcvDESKey() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append("Got RSA encrypted DES key from "+name+", \ndecrypted success\n");
				}
			});
		}
		
		private void rcvLog(String msg) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append(name+" -> server: \n"+msg+"\n");
					clientListComboBox.setSelectedItem(name);
				}
			});
		}
	}
	
	class ServerWriteHandler implements CompletionHandler<Integer, ByteBuffer>{

		private Client client;
		
		public ServerWriteHandler(Client client) {
				this.client = client;
		}
		
		@Override
		public void completed(Integer result, ByteBuffer buffer) {
			//如果没有发送完，就继续发送直到完成
			if (buffer.hasRemaining())
				client.channel.write(buffer, buffer, this);
			else{
				if(!client.makeRSAKey) {
					RSAPublicKey publicKey = client.rsa.getRSAPublicKey();
					String n = publicKey.getN().toString();
					client.sendRSAPublicKey();
					client.makeRSAKey = true;
					serverHandle.sendMsg(n, client);
				}
				else if(!client.getDESKey){
					ByteBuffer readBuffer = ByteBuffer.allocate(1024);
					client.channel.read(readBuffer, readBuffer, new ServerReadHandler(client));
				}
			}
		}
		@Override
		public void failed(Throwable exc, ByteBuffer attachment) {
			try {
				client.channel.close();
			} catch (IOException e) {
			}
		}

	}
	
	private class ServerReadHandler implements CompletionHandler<Integer, ByteBuffer> {
		private Client client;
		public ServerReadHandler(Client client) {
			this.client = client;
		}
		//读取到消息后的处理
		@Override
		public void completed(Integer result, ByteBuffer attachment) {
			attachment.flip();
			byte[] message = new byte[attachment.remaining()];
			attachment.get(message);
			try {
				String msg = new String(message, "UTF-8");
				if(!client.getDESKey) {
					client.key = RSA.decry(msg, client.rsa.getRSAPrivateKey());
					System.out.println("RSA decrypt result: "+client.key);
					client.rcvDESKey();
					client.prepareDone();
					client.getDESKey = true;
					client.des=new DES(client.key);
					ByteBuffer readBuffer = ByteBuffer.allocate(1024);
					client.channel.read(readBuffer, readBuffer, new ServerReadHandler(client));
				}
				else if(!msg.equals("END")) {
                	System.out.println("DES decry binary source: "+msg);
                	String res=client.des.getResult(msg, false);//DES解密
                	System.out.println("DES decry result: "+res);
                    client.rcvLog(res);//将解密后的消息输出到对话框
                    ByteBuffer readBuffer = ByteBuffer.allocate(1024);
    				client.channel.read(readBuffer, readBuffer, new ServerReadHandler(client));
                }
				else {
					client.channel.shutdownInput();
					client.channel.shutdownOutput();
					client.channel.close();
					serverHandle.deleteClient(client.name);
				}
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
			}
		}
		@Override
		public void failed(Throwable exc, ByteBuffer attachment) {
			try {
				client.channel.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private class AcceptHandler implements CompletionHandler<AsynchronousSocketChannel, AsyncServerHandler>{

		@Override
		public void completed(AsynchronousSocketChannel channel, AsyncServerHandler serverHandler) {
			if (count > 50) {
				JOptionPane.showMessageDialog(null, "The count of clients cannot be more than 50!","Error",JOptionPane.ERROR_MESSAGE);
				return;
			}
			count++;
			index++;
			String name = "client_"+index;
			Client client = new Client(name, channel);
            clients.put("client_"+index, client);
            addClient(channel);
			serverHandler.channel.accept(serverHandler, this); //继续接受其他客户端的请求
			//聊天前首先向客户端发送RSA公钥
			client.prepare();
			if(!client.makeRSAKey) {
				client.genRSAPublicKey();
				client.rsa = new RSA(512);
				RSAPublicKey publicKey = client.rsa.getRSAPublicKey();
				String e = publicKey.getE().toString();
				serverHandle.sendMsg(e, client);
			}
			else {
				ByteBuffer buffer = ByteBuffer.allocate(1024);
				client.channel.read(buffer, buffer, new ServerReadHandler(client));
			}
		}

		@Override
		public void failed(Throwable exc, AsyncServerHandler serverHandler) {
			exc.printStackTrace();
			serverHandler.latch.countDown();
		}

		private void addClient(AsynchronousSocketChannel channel) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					clientCountLabel.setText("客户端数量："+count);		
					clientListComboBox.addItem("client_"+index);
					int clientPort = 0;
					String ip=null;
					SocketAddress addr = null;
					try {
						addr = channel.getRemoteAddress();
					} catch (IOException e) {
						// TODO 自动生成的 catch 块
						e.printStackTrace();
					}
					if (addr instanceof InetSocketAddress) {
						clientPort = ((InetSocketAddress)addr).getPort();
						ip = ((InetSocketAddress)addr).getHostString();
					}
					workLog.append("server: got connection from "+ip+", \nport "+clientPort+", client_"+index+"\n");
				}
			});
		}
	}
	
	private class AsyncServerHandler implements Runnable{
		public CountDownLatch latch;
		public AsynchronousServerSocketChannel channel;
		private int port;
		public AsyncServerHandler(int port) {
			this.port = port;
			try {
				//创建服务端通道
				channel = AsynchronousServerSocketChannel.open();
				//绑定端口
				channel.bind(new InetSocketAddress(port));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		@Override
		public void run() {
			//CountDownLatch可以允许当前的现场一直阻塞，防止在执行过程中意外退出，
			//起到线程同步的作用
			System.out.println("Server Started");
			latch = new CountDownLatch(1);
			updateListenState();
			//用于接收客户端的连接
			channel.accept(this,new AcceptHandler());
			try {
				latch.await();
			} catch (InterruptedException e) {
				e.printStackTrace();
			} finally {
				if(exit)
					System.exit(0);
			}
		}
		
		private void updateListenState() {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					serverIPLabel.setText("IP：127.0.0.1");
					serverPortLabel.setText("端口号：2000");
					workLog.append("Listening...\n");
				}
			});
		}
		
		public void sendMsg(String msg, Client client){
			byte[] req = msg.getBytes();
			ByteBuffer writeBuffer = ByteBuffer.allocate(req.length);
			writeBuffer.put(req);
			writeBuffer.flip();
			client.channel.write(writeBuffer, writeBuffer,new ServerWriteHandler(client));
		}
		
		private void deleteClient(String name) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					workLog.append(name+" quit\n");
					clients.remove(name);
					if(clients.size()==0) {
						sendMsg.setEnabled(false);
					}
					int i=0;
					boolean find=false;
					for(;i<clientListComboBox.getItemCount();i++) {
						if(clientListComboBox.getItemAt(i).toString().equals(name)) {
							find=true;
							break;
						}	
					}
					if(find) {
						clientListComboBox.removeItemAt(i);
					}
					count--;
					clientCountLabel.setText("客户端数量："+count);
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
					DESServer frame = new DESServer();
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

	/**
	 * Create the frame.
	 */
	public DESServer() {
		setSkin();
		setIconImage(Toolkit.getDefaultToolkit().getImage(this.getClass().getResource("/img/smile.png")));
		setResizable(false);
		setTitle("DESServer");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 706, 429);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		subpanel1 = new JPanel();
		subpanel1.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "服务器工作日志", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		subpanel1.setBounds(10, 10, 330, 368);
		contentPane.add(subpanel1);
		subpanel1.setLayout(new MigLayout("", "[318px]", "[330px]"));
		
		scrollPane = new JScrollPane();
		subpanel1.add(scrollPane, "cell 0 0,grow");
		
		workLog = new JTextArea();
		workLog.setEditable(false);
		scrollPane.setViewportView(workLog);
		
		subpanel2 = new JPanel();
		subpanel2.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "服务器信息", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		subpanel2.setBounds(361, 10, 318, 132);
		contentPane.add(subpanel2);
		subpanel2.setLayout(new MigLayout("", "[96px]", "[29px][29px][29px]"));
		
		serverIPLabel = new JLabel("IP：");
		subpanel2.add(serverIPLabel, "cell 0 0,alignx left,aligny center");
		
		serverPortLabel = new JLabel("端口号：");
		subpanel2.add(serverPortLabel, "cell 0 1,alignx left,aligny center");
		
		maxclientLabel = new JLabel("最大客户端数量：50");
		subpanel2.add(maxclientLabel, "cell 0 2");
		
		subpanel3 = new JPanel();
		subpanel3.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "向客户端发送消息", TitledBorder.CENTER, TitledBorder.TOP, null, null));
		subpanel3.setBounds(361, 151, 318, 227);
		contentPane.add(subpanel3);
		subpanel3.setLayout(new MigLayout("", "[30px][162px][100px]", "[][37px][132px][37px]"));
		
		lblNewLabel = new JLabel("发送至：");
		subpanel3.add(lblNewLabel, "cell 0 1,alignx left,aligny center");
		
		clientListComboBox = new JComboBox();
		subpanel3.add(clientListComboBox, "cell 1 1,grow");
		clientListComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String temp = (String)clientListComboBox.getSelectedItem();
				if (temp == null) return;
				if (clients.get(temp).prepare) {
					sendMsg.setEnabled(false);
				}
				else {
					sendMsg.setEnabled(true);
				}
			}
		});
		
		scrollPane_1 = new JScrollPane();
		subpanel3.add(scrollPane_1, "cell 0 2 3 1,grow");
		
		editMsg = new JTextArea();
		scrollPane_1.setViewportView(editMsg);
		
		clientCountLabel = new JLabel("客户端数量：0");
		subpanel3.add(clientCountLabel, "flowx,cell 0 3 3 1,alignx left,aligny center");
		
		sendMsg = new JButton("发送");
		sendMsg.setEnabled(false);
		sendMsg.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if(editMsg.getText().length()==0) {
					JOptionPane.showMessageDialog(null, "消息内容不能为空！","Warning",JOptionPane.WARNING_MESSAGE);
					return;
				}
				String select=clientListComboBox.getSelectedItem().toString();//选择要发送的客户端
				Client client=clients.get(select);//获取与该客户端通信的线程和套接字
				if(client==null) {
					JOptionPane.showMessageDialog(null, "此客户端不存在！","Error",JOptionPane.WARNING_MESSAGE);
					return;
				}
				String temp = null, response = null;
				response=editMsg.getText().trim();//从输入框获取要发送的原文
				System.out.println("DES encry source: "+response);
                temp=client.des.getResult(response, true);//DES加密
                System.out.println("DES encry binary result: "+temp);
                serverHandle.sendMsg(temp, client);
                workLog.append("server -> "+select+": \n"+response+"\n");
				editMsg.setText("");//发送后清空输入框
			}
		});
		subpanel3.add(sendMsg, "cell 2 3,grow");
		
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				editMsg.requestFocus();
			}
			
			@Override
		    public void windowClosing(WindowEvent e) {
				String temp = (String)clientListComboBox.getSelectedItem();
				if (temp == null) {
					exit=true;
					serverHandle.latch.countDown();
				}
				else {
					boolean find=false;
					for (String client : clients.keySet()) {
						if (clients.get(client).prepare) {
							find=true;
							break;
						}
					}
					if (!find) {
						exit=true;
						serverHandle.latch.countDown();
					}
				}
		    }
		});
		
		serverHandle = new AsyncServerHandler(2000);
		new Thread(serverHandle,"Server").start();
	}
}
