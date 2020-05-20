package com.deschatv2.server;

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

import com.deschatv2.alg.*;

import net.miginfocom.swing.MigLayout;
import javax.swing.JComboBox;

import java.net.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;

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
	
	/** 客户端服务线程集合 */
	private Map<String,ServerThread> clients=new HashMap<String,ServerThread>();
	
	/** 客户端数量 */
	private int count;
	
	/** 客户端编号 */
	private int index;
	
	/**
	 * 服务器监听线程
	 * @author user
	 */
	private class ListenThread extends Thread {
		private ServerSocket s;
		public ListenThread() {
			start();
		}
		
		@Override
		public void run() {
			Socket socket=null;
			try {
				InetAddress address = InetAddress.getByName("127.0.0.1");
				s=new ServerSocket(2000,50,address);//建立监听套接字，最大连接数50
				System.out.println("Server Started");
				updateListenState();
				while(true) { //不断监听并接受客户端的连接请求，没有连接请求则一直在这里阻塞
					socket=s.accept();//接受客户端的连接请求
					socket.setSoTimeout(0);//设置读取超时为0
					count++;
					index++;
					InetAddress clientAddress=socket.getInetAddress();//获取客户端的连接
					addClient(socket,clientAddress);
					//新建并启动一个为新客户端服务的线程
	                ServerThread thread=new ServerThread("client_"+index,clientAddress,socket);
	                clients.put("client_"+index, thread);
	                thread.start();//启动线程
				}
			} 
			catch (IOException e) {
				// TODO 自动生成的 catch 块
				e.printStackTrace();
				System.out.println("IOException: "+e.getMessage());
				if(socket!=null) {
					try {
						socket.close();
					} catch (IOException e1) {
						// TODO 自动生成的 catch 块
						e1.printStackTrace();
						System.out.println("IOException: "+e1.getMessage());
					}
				}
			}
			finally {
				try {
					s.close();
				} catch (IOException e) {
					// TODO 自动生成的 catch 块
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
				}
				finally {
					if(exit) {
						System.exit(0);
					}
				}
			}
		}
		
		private void addClient(Socket socket,InetAddress addr) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					clientCountLabel.setText("客户端数量："+count);		
					clientListComboBox.addItem("client_"+index);
					String ip=addr.toString();
					workLog.append("server: got connection from "+ip.substring(1)+", \nport "+socket.getPort()+", client_"+index+"\n");
				}
			});
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
	}
	
	/**
	 * 服务器和客户端聊天线程
	 * @author user
	 */
	private class ServerThread extends Thread {
		public String name;
		private InetAddress address;
		private Socket socket;
		private int port;
		public volatile boolean send=false;
		private volatile boolean makeRSAKey=false;
		private volatile boolean getDESKey=false;
		public volatile boolean prepare=true;
		private String key;
		private RSA rsa;
		public ServerThread(String n,InetAddress addr,Socket s) {
			name=n;
			address=addr;
			socket=s;
			port=socket.getPort();
		}
		
		public String getDESKey() {
			return key;
		}
		
		public Socket getSocket() {
			return socket;
		}
		
		@Override
		public void run() {
			InputStream in = null;
			OutputStream out = null;
			InputStreamReader ir = null;
            BufferedReader br = null;
			try {
				in = socket.getInputStream();//获取TCP连接的输入字节流
				out = socket.getOutputStream();
				ir = new InputStreamReader(in);//将TCP字节流转为字符流
                br = new BufferedReader(ir);//带缓冲区的文本读取
				//聊天前首先向客户端发送RSA公钥
				prepare();
				if(!makeRSAKey) {
					genRSAPublicKey();
					rsa = new RSA(512);
					RSAPublicKey publicKey = rsa.getRSAPublicKey();
					String e = publicKey.getE().toString();
					String n = publicKey.getN().toString();
					e += "\n";
					n += "\n";
					sendRSAPublicKey();
					out.write(e.getBytes());
					out.flush();
					out.write(n.getBytes());
					out.flush();
				}
				if(!getDESKey) {
					String temp = br.readLine();
					key = RSA.decry(temp, rsa.getRSAPrivateKey());
					System.out.println("RSA decrypt result: "+key);
					rcvDESKey();
				}
				prepareDone();
				DES des=new DES(key);
				String receiveMsg = null;
                //接收消息并解密，不同消息的边界为换行符
                while ((receiveMsg = br.readLine()) != null) {
                	if(receiveMsg.equals("END")) break;
                	System.out.println("DES decry binary source: "+receiveMsg);
                	String res=des.getResult(receiveMsg, false);//DES解密
                	System.out.println("DES decry result: "+res);
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
					deleteClient();
					if(exit) {
						System.exit(0);
					}
				}
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
		
		private void deleteClient() {
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
				ServerThread thread=clients.get(select);//获取与该客户端通信的线程和套接字
				if(thread==null) {
					JOptionPane.showMessageDialog(null, "此客户端不存在！","Error",JOptionPane.WARNING_MESSAGE);
					return;
				}
				Socket s=thread.getSocket();
				try {
					OutputStream out;
					String response,temp;
					DES des=new DES(thread.getDESKey());
					out = s.getOutputStream();//获取TCP连接的输出字节流
					response=editMsg.getText().trim();//从输入框获取要发送的原文
					System.out.println("DES encry source: "+response);
	                temp=des.getResult(response, true);//DES加密
	                System.out.println("DES encry binary result: "+temp);
	                temp+="\n";//消息边界为换行符（不需要加密），不加边界会一直阻塞
	                out.write(temp.getBytes());//以字节形式发送加密后的消息
	                out.flush();//清空缓冲区数据
	                workLog.append("server -> "+select+": \n"+response+"\n");
					editMsg.setText("");//发送后清空输入框
				}
				catch(IOException e) {
					e.printStackTrace();
					System.out.println("IOException: "+e.getMessage());
				}
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
					return;
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
					}
				}
		    }
		});
		
		new ListenThread();
	}
}
