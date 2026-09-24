package com.googletv.kumanda;

import android.Manifest;
import android.bluetooth.*;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import android.content.SharedPreferences;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.net.ssl.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {

    enum Mode { WIFI_ADB, BT, PIN }
    Mode currentMode = Mode.WIFI_ADB;

    int ses=24, kanal=7;
    TextView volText,chText,statusText;
    EditText ipInput, ipPinInput, pinCodeInput;
    LinearLayout wifiLayout, btLayout, pinLayout;
    Spinner btSpinner;
    ArrayAdapter<String> btAdapter;
    List<BluetoothDevice> btDevices=new ArrayList<>();
    BluetoothAdapter btAdapterHW;
    BluetoothSocket btSocket;
    OutputStream btOut;

    // WiFi ADB
    Socket adbSocket; DataInputStream adbIn; DataOutputStream adbOut; boolean adbConnected=false; int localId=1;
    static final int A_CNXN=0x4e584e43, A_OPEN=0x4e45504f;

    // PIN Pairing
    Socket pinSocket; DataInputStream pinIn; DataOutputStream pinOut;
    Socket remoteSocket; DataOutputStream remoteOut; DataInputStream remoteIn;
    KeyPair clientKeyPair; X509Certificate clientCert; byte[] serverModulus, serverExponent, clientModulus, clientExponent;
    String currentIp=""; boolean pinPaired=false;

    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        volText=findViewById(R.id.volText); chText=findViewById(R.id.chText); statusText=findViewById(R.id.statusText);
        ipInput=findViewById(R.id.ipInput); ipPinInput=findViewById(R.id.ipPinInput); pinCodeInput=findViewById(R.id.pinCodeInput);
        wifiLayout=findViewById(R.id.wifiLayout); btLayout=findViewById(R.id.btLayout); pinLayout=findViewById(R.id.pinLayout);
        btSpinner=findViewById(R.id.btSpinner);
        btAdapterHW=BluetoothAdapter.getDefaultAdapter();
        btAdapter=new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new ArrayList<>());
        btAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        btSpinner.setAdapter(btAdapter);
        SharedPreferences prefs=getSharedPreferences("gtv",MODE_PRIVATE);
        ipInput.setText(prefs.getString("tv_ip","")); ipPinInput.setText(prefs.getString("tv_ip",""));

        RadioGroup modeGroup=findViewById(R.id.modeGroup);
        modeGroup.setOnCheckedChangeListener((g,id)->{
            if(id==R.id.radioWifiAdb){ currentMode=Mode.WIFI_ADB; wifiLayout.setVisibility(LinearLayout.VISIBLE); btLayout.setVisibility(LinearLayout.GONE); pinLayout.setVisibility(LinearLayout.GONE); statusText.setText(adbConnected?"WiFi ADB Bagli":"WiFi ADB - IP gir"); }
            else if(id==R.id.radioBt){ currentMode=Mode.BT; wifiLayout.setVisibility(LinearLayout.GONE); btLayout.setVisibility(LinearLayout.VISIBLE); pinLayout.setVisibility(LinearLayout.GONE); statusText.setText("BT - Tara ve Baglan"); checkPerm(); }
            else { currentMode=Mode.PIN; wifiLayout.setVisibility(LinearLayout.GONE); btLayout.setVisibility(LinearLayout.GONE); pinLayout.setVisibility(LinearLayout.VISIBLE); statusText.setText("PIN Mod - Kodu Goster'e bas, TV'de kod cikacak"); }
        });

        // WIFI ADB
        findViewById(R.id.btnWifiConnect).setOnClickListener(v->{
            String ip=ipInput.getText().toString().trim();
            if(ip.isEmpty()){ toast("IP gir"); return; }
            prefs.edit().putString("tv_ip",ip).apply(); ipPinInput.setText(ip); currentIp=ip;
            connectAdb(ip);
        });

        // BT
        findViewById(R.id.btnBtEnable).setOnClickListener(v->{
            if(btAdapterHW==null){ toast("BT yok"); return; }
            if(!btAdapterHW.isEnabled()){
                if(ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){ ActivityCompat.requestPermissions(this,new String[]{Manifest.permission.BLUETOOTH_CONNECT},1); return; }
                btAdapterHW.enable(); toast("BT aciliyor");
            } else toast("BT zaten acik");
        });
        findViewById(R.id.btnBtScan).setOnClickListener(v->scanBt());
        findViewById(R.id.btnBtConnect).setOnClickListener(v->{
            if(btDevices.isEmpty()){ toast("Once Tara"); return; }
            int pos=btSpinner.getSelectedItemPosition();
            if(pos<0||pos>=btDevices.size()){ toast("Cihaz sec"); return; }
            connectBt(btDevices.get(pos));
        });

        // PIN - 3. MOD - TV'de kod goster
        findViewById(R.id.btnPinStart).setOnClickListener(v->{
            String ip=ipPinInput.getText().toString().trim();
            if(ip.isEmpty()) ip=ipInput.getText().toString().trim();
            if(ip.isEmpty()){ toast("TV IP gir"); return; }
            prefs.edit().putString("tv_ip",ip).apply(); currentIp=ip;
            startPinPairing(ip);
        });
        findViewById(R.id.btnPinSend).setOnClickListener(v->{
            String code=pinCodeInput.getText().toString().trim();
            if(code.isEmpty()){ toast("TV'deki kodu gir (örn 4D35)"); return; }
            sendPinSecret(code);
        });
        findViewById(R.id.btnPinConnectRemote).setOnClickListener(v->{
            String ip=ipPinInput.getText().toString().trim();
            if(ip.isEmpty()) ip=currentIp;
            if(ip.isEmpty()){ toast("IP gir"); return; }
            connectRemote6466(ip);
        });

        // Kumanda - 3 modda da calisir
        findViewById(R.id.btnPower).setOnClickListener(v->sendCommand(26,"POWER"));
        findViewById(R.id.btnMute).setOnClickListener(v->sendCommand(164,"MUTE"));
        findViewById(R.id.btnUp).setOnClickListener(v->sendCommand(19,"UP"));
        findViewById(R.id.btnDown).setOnClickListener(v->sendCommand(20,"DOWN"));
        findViewById(R.id.btnLeft).setOnClickListener(v->sendCommand(21,"LEFT"));
        findViewById(R.id.btnRight).setOnClickListener(v->sendCommand(22,"RIGHT"));
        findViewById(R.id.btnOk).setOnClickListener(v->sendCommand(23,"OK"));
        findViewById(R.id.btnBack).setOnClickListener(v->sendCommand(4,"BACK"));
        findViewById(R.id.btnHome).setOnClickListener(v->sendCommand(3,"HOME"));
        findViewById(R.id.btnMenu).setOnClickListener(v->sendCommand(82,"MENU"));
        findViewById(R.id.btnVolUp).setOnClickListener(v->sendCommand(24,"VOL_UP",()->{ if(ses<100)ses++; updateUI(); }));
        findViewById(R.id.btnVolDown).setOnClickListener(v->sendCommand(25,"VOL_DOWN",()->{ if(ses>0)ses--; updateUI(); }));
        findViewById(R.id.btnChUp).setOnClickListener(v->sendCommand(166,"CH_UP",()->{ kanal++; if(kanal>999)kanal=1; updateUI(); }));
        findViewById(R.id.btnChDown).setOnClickListener(v->sendCommand(167,"CH_DOWN",()->{ kanal--; if(kanal<1)kanal=999; updateUI(); }));
        updateUI();
    }

    // ============ 1. WIFI ADB ============
    void connectAdb(String ip){
        statusText.setText("WiFi ADB baglaniyor "+ip+":5555");
        new Thread(()->{
            try{
                if(adbSocket!=null) try{adbSocket.close();}catch(Exception e){}
                adbSocket=new Socket(); adbSocket.connect(new java.net.InetSocketAddress(ip,5555),5000);
                adbIn=new DataInputStream(adbSocket.getInputStream()); adbOut=new DataOutputStream(adbSocket.getOutputStream());
                sendAdb(A_CNXN,0x01000000,256*1024,"host::\0".getBytes());
                AdbMsg r=readAdb();
                adbConnected=true;
                runOnUiThread(()->{ statusText.setText("WiFi ADB Bagli: "+ip); toast("ADB Baglandi"); });
            }catch(Exception e){
                adbConnected=false;
                runOnUiThread(()->{ statusText.setText("WiFi ADB hata: "+e.getMessage()); toast("Baglanamadi: Ag Hata Ayiklama AC"); });
            }
        }).start();
    }
    void sendAdb(int cmd,int a0,int a1,byte[] data) throws IOException{
        if(data==null) data=new byte[0];
        ByteBuffer b=ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(cmd); b.putInt(a0); b.putInt(a1); b.putInt(data.length); b.putInt(checksum(data)); b.putInt(cmd ^ 0xFFFFFFFF);
        adbOut.write(b.array()); if(data.length>0) adbOut.write(data); adbOut.flush();
    }
    AdbMsg readAdb() throws IOException{
        byte[] h=new byte[24]; adbIn.readFully(h);
        ByteBuffer b=ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        int cmd=b.getInt(),a0=b.getInt(),a1=b.getInt(),len=b.getInt(),crc=b.getInt(),mag=b.getInt();
        byte[] d=new byte[len]; if(len>0) adbIn.readFully(d);
        return new AdbMsg(cmd,a0,a1,d);
    }
    int checksum(byte[] d){ int s=0; for(byte x:d) s+=x&0xFF; return s; }
    static class AdbMsg{ int c,a0,a1; byte[] d; AdbMsg(int c,int a0,int a1,byte[] d){this.c=c;this.a0=a0;this.a1=a1;this.d=d;} }
    void execAdb(int keyCode){
        if(!adbConnected) return;
        new Thread(()->{
            try{
                String cmd="shell:input keyevent "+keyCode+"\0";
                sendAdb(A_OPEN,localId++,0,cmd.getBytes());
                for(int i=0;i<2;i++) try{readAdb();}catch(Exception e){}
            }catch(Exception e){}
        }).start();
    }

    // ============ 2. BLUETOOTH ============
    void scanBt(){
        checkPerm();
        if(btAdapterHW==null||!btAdapterHW.isEnabled()){ toast("BT acik degil"); return; }
        if(ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){ ActivityCompat.requestPermissions(this,new String[]{Manifest.permission.BLUETOOTH_CONNECT},1); return; }
        Set<BluetoothDevice> paired=btAdapterHW.getBondedDevices();
        btDevices.clear(); List<String> names=new ArrayList<>();
        for(BluetoothDevice d:paired){ btDevices.add(d); names.add(d.getName()+" ("+d.getAddress()+")"); }
        if(names.isEmpty()) names.add("Eslesmis cihaz yok - Ayarlardan eslestir");
        btAdapter.clear(); btAdapter.addAll(names); btAdapter.notifyDataSetChanged();
        toast(names.size()+" cihaz bulundu");
    }
    void connectBt(BluetoothDevice dev){
        if(ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){ ActivityCompat.requestPermissions(this,new String[]{Manifest.permission.BLUETOOTH_CONNECT},1); return; }
        statusText.setText("BT baglaniyor: "+dev.getName());
        new Thread(()->{
            try{
                java.util.UUID uuid=java.util.UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
                btSocket=dev.createRfcommSocketToServiceRecord(uuid);
                btSocket.connect(); btOut=btSocket.getOutputStream();
                runOnUiThread(()->{ statusText.setText("BT Bagli: "+dev.getName()); toast("BT Baglandi"); });
            }catch(Exception e){ runOnUiThread(()->{ statusText.setText("BT hata: "+e.getMessage()); toast("BT baglanamadi"); }); }
        }).start();
    }
    void checkPerm(){
        List<String> p=new ArrayList<>();
        if(ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED) p.add(Manifest.permission.BLUETOOTH_CONNECT);
        if(ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)!=PackageManager.PERMISSION_GRANTED) p.add(Manifest.permission.BLUETOOTH_SCAN);
        if(ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)!=PackageManager.PERMISSION_GRANTED) p.add(Manifest.permission.ACCESS_FINE_LOCATION);
        if(!p.isEmpty()) ActivityCompat.requestPermissions(this,p.toArray(new String[0]),1);
    }

    // ============ 3. PIN PAIRING - TV'de Kod Gosterir ============
    void startPinPairing(String ip){
        statusText.setText("PIN Pairing basliyor "+ip+":6467 - TV'de kod cikacak");
        new Thread(()->{
            try{
                generateClientCert();
                SSLSocketFactory factory = createTrustAllSslFactory();
                SSLSocket socket = (SSLSocket) factory.createSocket(ip, 6467);
                socket.setSoTimeout(10000);
                socket.startHandshake();

                // Server cert al
                X509Certificate serverCert = (X509Certificate) socket.getSession().getPeerCertificates()[0];
                RSAPublicKey serverPub = (RSAPublicKey) serverCert.getPublicKey();
                serverModulus = serverPub.getModulus().toByteArray();
                serverExponent = serverPub.getPublicExponent().toByteArray();
                RSAPublicKey clientPub = (RSAPublicKey) clientKeyPair.getPublic();
                clientModulus = clientPub.getModulus().toByteArray();
                clientExponent = clientPub.getPublicExponent().toByteArray();

                pinSocket = socket;
                pinIn = new DataInputStream(socket.getInputStream());
                pinOut = new DataOutputStream(socket.getOutputStream());

                // 1. PAIRING_REQUEST type 10
                JSONObject req = new JSONObject();
                req.put("protocol_version",1);
                JSONObject payload = new JSONObject();
                payload.put("service_name","androidtvremote");
                payload.put("client_name","GTV Kumanda");
                req.put("payload",payload);
                req.put("type",10); req.put("status",200);
                sendJson(req);

                // 2. OPTIONS ack bekle, OPTIONS gonder
                JSONObject resp = readJson();
                if(resp!=null && resp.optInt("type")==11){
                    JSONObject opt = new JSONObject();
                    opt.put("protocol_version",1);
                    JSONObject p2 = new JSONObject();
                    p2.put("output_encodings", new org.json.JSONArray().put(new JSONObject().put("symbol_length",4).put("type",3)));
                    p2.put("input_encodings", new org.json.JSONArray().put(new JSONObject().put("symbol_length",4).put("type",3)));
                    p2.put("preferred_role",1);
                    opt.put("payload",p2); opt.put("type",20); opt.put("status",200);
                    sendJson(opt);
                    JSONObject resp2 = readJson();
                    // 3. CONFIGURATION
                    JSONObject cfg = new JSONObject();
                    cfg.put("protocol_version",1);
                    JSONObject p3 = new JSONObject();
                    p3.put("encoding", new JSONObject().put("symbol_length",4).put("type",3));
                    p3.put("client_role",1);
                    cfg.put("payload",p3); cfg.put("type",30); cfg.put("status",200);
                    sendJson(cfg);
                    JSONObject resp3 = readJson();
                    runOnUiThread(()->{
                        statusText.setText("TV'de 4 haneli KOD cikti! Kodu gir ve Dogrula'ya bas");
                        toast("TV ekranina bak - KOD cikti!");
                    });
                }
            }catch(Exception e){
                runOnUiThread(()->{ statusText.setText("PIN hata: "+e.getMessage()); toast("PIN basarisiz: "+e.getMessage()); });
            }
        }).start();
    }

    void sendPinSecret(String code){
        new Thread(()->{
            try{
                if(pinOut==null){ runOnUiThread(()->toast("Once Kodu Goster'e bas")); return; }
                // Secret hesapla: SHA256(clientMod + clientExp + serverMod + serverExp + last2chars)
                String last2 = code.length()>=2 ? code.substring(code.length()-2) : code;
                byte[] codeBin;
                try{ codeBin = hexStringToByteArray(last2); }catch(Exception ex){ codeBin = last2.getBytes(); }

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(trimLeadingZero(clientModulus));
                md.update(trimLeadingZero(clientExponent));
                md.update(trimLeadingZero(serverModulus));
                md.update(trimLeadingZero(serverExponent));
                md.update(codeBin);
                byte[] hash = md.digest();
                String secret = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP);

                JSONObject sec = new JSONObject();
                sec.put("protocol_version",1);
                JSONObject p = new JSONObject();
                p.put("secret",secret);
                sec.put("payload",p); sec.put("type",40); sec.put("status",200);
                sendJson(sec);

                JSONObject resp = readJson();
                if(resp!=null && resp.optInt("type")==41){
                    pinPaired=true;
                    runOnUiThread(()->{ statusText.setText("PIN Dogrulandi! Simdi 6466 Baglan'a bas"); toast("Eslesme OK!"); });
                } else {
                    runOnUiThread(()->{ statusText.setText("PIN yanlis veya hata"); toast("Kod yanlis"); });
                }
            }catch(Exception e){
                runOnUiThread(()->{ statusText.setText("Secret hata: "+e.getMessage()); toast(e.getMessage()); });
            }
        }).start();
    }

    void connectRemote6466(String ip){
        statusText.setText("6466 Remote baglaniyor...");
        new Thread(()->{
            try{
                SSLSocketFactory factory = createTrustAllSslFactory();
                SSLSocket socket = (SSLSocket) factory.createSocket(ip, 6466);
                socket.startHandshake();
                remoteSocket = socket;
                remoteOut = new DataOutputStream(socket.getOutputStream());
                remoteIn = new DataInputStream(socket.getInputStream());

                // Config mesaj: [1,0,0,21,0,0,0,1,0,0,0,1,32,3,0,0,0,0,0,0,4,'t','e','s','t']
                byte[] cfg = new byte[]{1,0,0,21,0,0,0,1,0,0,0,1,32,3,0,0,0,0,0,0,4,116,101,115,116};
                remoteOut.write(cfg); remoteOut.flush();

                runOnUiThread(()->{ statusText.setText("Remote 6466 Bagli! Tuslar calisir"); toast("6466 Baglandi - Kumanda hazir"); });
            }catch(Exception e){
                runOnUiThread(()->{ statusText.setText("6466 hata: "+e.getMessage()); toast("6466 baglanamadi"); });
            }
        }).start();
    }

    void sendJson(JSONObject obj) throws IOException{
        String s=obj.toString();
        byte[] data=s.getBytes();
        ByteBuffer b=ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        b.putInt(data.length);
        pinOut.write(b.array()); pinOut.write(data); pinOut.flush();
    }
    JSONObject readJson() throws IOException{
        byte[] lenB=new byte[4]; pinIn.readFully(lenB);
        int len=ByteBuffer.wrap(lenB).order(ByteOrder.BIG_ENDIAN).getInt();
        if(len>10000) return null;
        byte[] data=new byte[len]; pinIn.readFully(data);
        try{ return new JSONObject(new String(data)); }catch(Exception e){ return null; }
    }

    SSLSocketFactory createTrustAllSslFactory() throws Exception{
        if(clientKeyPair==null) generateClientCert();
        KeyStore ks=KeyStore.getInstance("BKS");
        ks.load(null,null);
        ks.setKeyEntry("client", clientKeyPair.getPrivate(), "".toCharArray(), new java.security.cert.Certificate[]{clientCert});

        KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "".toCharArray());

        TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager(){
            public X509Certificate[] getAcceptedIssuers(){ return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c,String a){}
            public void checkServerTrusted(X509Certificate[] c,String a){}
        }};

        SSLContext ctx=SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), trustAll, new SecureRandom());
        return ctx.getSocketFactory();
    }

    void generateClientCert() throws Exception{
        KeyPairGenerator kpg=KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        clientKeyPair=kpg.generateKeyPair();

        X500Name dn=new X500Name("CN=atvremote");
        long now=System.currentTimeMillis();
        Date notBefore=new Date(now-1000L*60*60);
        Date notAfter=new Date(now+1000L*60*60*24*365*10);
        java.math.BigInteger serial=java.math.BigInteger.valueOf(now);

        X509v3CertificateBuilder builder=new JcaX509v3CertificateBuilder(dn,serial,notBefore,notAfter,dn,clientKeyPair.getPublic());
        ContentSigner signer=new JcaContentSignerBuilder("SHA256withRSA").build(clientKeyPair.getPrivate());
        clientCert=new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    byte[] trimLeadingZero(byte[] b){ if(b.length>1 && b[0]==0) return Arrays.copyOfRange(b,1,b.length); return b; }
    byte[] hexStringToByteArray(String s){
        int len=s.length(); byte[] data=new byte[len/2];
        for(int i=0;i<len;i+=2) data[i/2]=(byte)((Character.digit(s.charAt(i),16)<<4)+Character.digit(s.charAt(i+1),16));
        return data;
    }

    // Ortak komut gonderme 3 mod
    void sendCommand(int keyCode,String name){ sendCommand(keyCode,name,null); }
    void sendCommand(int keyCode,String name,Runnable ok){
        if(currentMode==Mode.WIFI_ADB){
            if(adbConnected){ execAdb(keyCode); toast(name+" -> WiFi ADB"); } else toast(name+" [WiFi bagli degil]");
        } else if(currentMode==Mode.BT){
            if(btSocket!=null && btSocket.isConnected() && btOut!=null){
                try{ btOut.write((name+"\n").getBytes()); toast(name+" -> BT"); }catch(Exception e){ toast("BT hata"); }
            } else toast(name+" [BT bagli degil]");
        } else { // PIN - 6466
            if(remoteOut!=null){
                try{
                    int counter=(int)(System.currentTimeMillis()%10000);
                    ByteBuffer b=ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
                    b.put(new byte[]{1,2,0,16}); b.putInt(0); b.putInt(0); b.putInt(counter); b.putInt(0); b.putInt(keyCode);
                    remoteOut.write(b.array()); remoteOut.flush();
                    ByteBuffer b2=ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
                    b2.put(new byte[]{1,2,0,16}); b2.putInt(0); b2.putInt(0); b2.putInt(counter+1); b2.putInt(1); b2.putInt(keyCode);
                    remoteOut.write(b2.array()); remoteOut.flush();
                    toast(name+" -> PIN 6466");
                }catch(Exception e){ toast("6466 hata: "+e.getMessage()); }
            } else toast(name+" [6466 bagli degil - Once PIN baglan]");
        }
        if(ok!=null) ok.run();
    }

    void updateUI(){ volText.setText(String.valueOf(ses)); chText.setText(String.valueOf(kanal)); }
    void toast(String s){ Toast.makeText(this,s,Toast.LENGTH_SHORT).show(); }
}
