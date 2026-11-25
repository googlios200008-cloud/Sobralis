package ru.sobralis.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.JavascriptInterface;
import android.webkit.JsResult;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import android.widget.Button;
import android.widget.LinearLayout;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class MainActivity extends Activity {
  private static final String ORIGIN = "https://appassets.androidplatform.net";
  private static final int PICK_JSON=42, SAVE_JSON=43, MAX_BACKUP=3*1024*1024;
  private static final Set<String> ASSETS=Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
      "/index.html","/style.css","/shared.css","/app.js","/enhancements.js","/party.js","/backup.js","/family.js","/shared.js","/trip-ui.js","/host-ui.js","/cloud.js","/android.js","/manifest.webmanifest","/hero-web.webp","/hero.png","/assets/icon-192.png","/assets/icon-512.png","/assets/nunito-cyrillic.woff2","/assets/nunito-latin.woff2")));
  private WebView web, onlineWeb;
  private OnlinePolicy onlinePolicy;
  private AlertDialog inviteDialog;
  private ValueCallback<Uri[]> picker;
  private byte[] pendingBackup;
  private boolean pendingRawRecovery;

  @Override public void onCreate(Bundle saved){
    super.onCreate(saved);
    web=new WebView(this);
    applyInsets(web);
    setContentView(web);
    WebSettings s=web.getSettings();
    s.setJavaScriptEnabled(true);s.setDomStorageEnabled(true);s.setCacheMode(WebSettings.LOAD_NO_CACHE);
    s.setAllowFileAccess(false);s.setAllowContentAccess(true);
    s.setAllowFileAccessFromFileURLs(false);s.setAllowUniversalAccessFromFileURLs(false);
    s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
    s.setJavaScriptCanOpenWindowsAutomatically(false);s.setSupportMultipleWindows(false);
    web.setBackgroundColor(Color.rgb(255,250,246));
    web.addJavascriptInterface(new BackupBridge(),"AndroidBackup");
    onlinePolicy=OnlinePolicy.fromOrigin(OnlineConfig.ORIGIN);
    if(onlinePolicy!=null)web.addJavascriptInterface(new OnlineBridge(),"AndroidOnline");
    web.setWebViewClient(new LocalClient());web.setWebChromeClient(new Chrome());
    web.loadUrl(ORIGIN+"/index.html");
    receiveInvitation(getIntent());
  }
  private void applyInsets(View target){
    if(Build.VERSION.SDK_INT>=35)target.setOnApplyWindowInsetsListener((v,insets)->{
      android.graphics.Insets bars=insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
      v.setPadding(bars.left,bars.top,bars.right,bars.bottom);return insets;
    });
  }
  private String bundledOnlineInit(){
    try(InputStream in=getAssets().open("online-init.js");ByteArrayOutputStream out=new ByteArrayOutputStream()){
      byte[] buf=new byte[4096];int n;while((n=in.read(buf))!=-1)out.write(buf,0,n);return new String(out.toByteArray(),StandardCharsets.UTF_8);
    }catch(IOException e){return "";}
  }
  private static boolean local(Uri u){return "https".equals(u.getScheme()) && "appassets.androidplatform.net".equals(u.getHost()) && u.getPort()==-1 && u.getUserInfo()==null;}
  private static WebResourceResponse response(int status,String reason,String mime,String encoding,byte[] body){
    Map<String,String> headers=new HashMap<>();headers.put("Cache-Control","no-store");headers.put("X-Content-Type-Options","nosniff");
    headers.put("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; form-action 'none'");
    return new WebResourceResponse(mime,encoding,status,reason,headers,new ByteArrayInputStream(body));
  }
  private final class LocalClient extends WebViewClient {
    @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r){
      Uri u=r.getUrl();return !local(u) || !"/index.html".equals(u.getEncodedPath());
    }
    @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest request){
      Uri u=request.getUrl();String path=u.getEncodedPath();
      if(!local(u) || !"GET".equals(request.getMethod()) || !ASSETS.contains(path))
        return response(404,"Not Found","text/plain","UTF-8",new byte[0]);
      String mime=path.endsWith(".html")?"text/html":path.endsWith(".css")?"text/css":path.endsWith(".js")?"application/javascript":path.endsWith(".webmanifest")?"application/manifest+json":path.endsWith(".woff2")?"font/woff2":path.endsWith(".webp")?"image/webp":"image/png";
      try {
        Map<String,String> headers=new HashMap<>();headers.put("Cache-Control","no-store");headers.put("X-Content-Type-Options","nosniff");
        headers.put("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; form-action 'none'");
        return new WebResourceResponse(mime,(mime.startsWith("text/")||mime.contains("javascript")||mime.contains("json"))?"UTF-8":null,200,"OK",headers,getAssets().open("web"+path));
      }catch(IOException e){return response(404,"Not Found","text/plain","UTF-8",new byte[0]);}
    }
  }
  // The connected prototype is intentionally a second WebView. It has no
  // JavaScript bridge, cannot access the local WebView's origin/storage and
  // never accepts an origin supplied by web content.
  private final class OnlineBridge {
    @JavascriptInterface public void open(){runOnUiThread(()->openOnline());}
  }
  private void openOnline(){openOnline("/index.html");}
  private void openOnline(String initialPath){
    if(onlinePolicy==null)return;
    if(onlineWeb!=null){onlineWeb.loadUrl(OnlineConfig.ORIGIN+initialPath);return;}
    onlineWeb=new WebView(this);onlineWeb.setVisibility(View.INVISIBLE);WebSettings s=onlineWeb.getSettings();
    s.setJavaScriptEnabled(true);s.setDomStorageEnabled(true);s.setAllowFileAccess(false);s.setAllowContentAccess(false);
    s.setAllowFileAccessFromFileURLs(false);s.setAllowUniversalAccessFromFileURLs(false);
    s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);s.setJavaScriptCanOpenWindowsAutomatically(false);s.setSupportMultipleWindows(false);
    android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(onlineWeb,false);
    onlineWeb.setWebViewClient(new WebViewClient(){
      @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r){return !onlinePolicy.allowsNavigation(r.getUrl().toString());}
      @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest r){
        if(!onlinePolicy.allows(r.getUrl().toString()))return response(403,"Forbidden","text/plain","UTF-8",new byte[0]);
        return null;
      }
      @Override public void onReceivedError(WebView v,WebResourceRequest r,android.webkit.WebResourceError error){if(r.isForMainFrame()&&v==onlineWeb)v.setVisibility(View.VISIBLE);}
      @Override public void onPageFinished(WebView v,String url){
        super.onPageFinished(v,url);
        if(!onlinePolicy.allowsNavigation(url))return;
        Uri uri=Uri.parse(url);String p=uri.getEncodedPath();
        if(p==null||p.isEmpty()||"/".equals(p)||"/index.html".equals(p))v.evaluateJavascript(bundledOnlineInit(),ignored->{if(v==onlineWeb)v.setVisibility(View.VISIBLE);});
        else if(v==onlineWeb)v.setVisibility(View.VISIBLE);
      }
    });
    // No file chooser and no native bridge in the remotely served WebView.
    onlineWeb.setWebChromeClient(new WebChromeClient(){
      @Override public boolean onJsAlert(WebView v,String url,String msg,JsResult result){new AlertDialog.Builder(MainActivity.this).setMessage(msg).setPositiveButton("OK",(d,w)->result.confirm()).setOnCancelListener(d->result.cancel()).show();return true;}
      @Override public boolean onJsConfirm(WebView v,String url,String msg,JsResult result){new AlertDialog.Builder(MainActivity.this).setMessage(msg).setPositiveButton("Да",(d,w)->result.confirm()).setNegativeButton("Отмена",(d,w)->result.cancel()).setOnCancelListener(d->result.cancel()).show();return true;}
    });
    LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);applyInsets(layout);
    Button back=new Button(this);back.setText("← На устройство");back.setOnClickListener(v->closeOnline());layout.addView(back,new LinearLayout.LayoutParams(-1,-2));
    layout.addView(onlineWeb,new LinearLayout.LayoutParams(-1,0,1));setContentView(layout);onlineWeb.loadUrl(OnlineConfig.ORIGIN+initialPath);
  }
  @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);receiveInvitation(intent);}
  private void receiveInvitation(Intent intent){
    if(intent==null||!Intent.ACTION_VIEW.equals(intent.getAction())||onlinePolicy==null)return;
    Uri data=intent.getData();String target=data==null?null:onlinePolicy.invitePath(data.toString());
    // Avoid retaining the original bearer-bearing intent as this Activity's
    // current intent. Android or the sending application may still retain it.
    setIntent(new Intent(Intent.ACTION_MAIN));
    if(target==null){message("Ссылка приглашения недоступна");return;}
    if(inviteDialog!=null&&inviteDialog.isShowing()){message("Сначала завершите открытие предыдущей ссылки");return;}
    inviteDialog=new AlertDialog.Builder(this).setTitle("Приглашение в «Собрались!»")
      .setMessage("Открыть приглашение в тестовом совместном режиме? Ваши локальные данные не переносятся. Участие потребуется подтвердить отдельно.")
      .setPositiveButton("Открыть",(d,w)->openOnline(target)).setNegativeButton("Отмена",null).create();
    inviteDialog.setOnDismissListener(d->inviteDialog=null);inviteDialog.show();
  }
  private void closeOnline(){
    if(onlineWeb==null)return;disposeOnline();setContentView(web);
  }
  private void disposeOnline(){WebView old=onlineWeb;onlineWeb=null;if(old!=null){old.stopLoading();if(old.getParent() instanceof ViewGroup)((ViewGroup)old.getParent()).removeView(old);old.destroy();}}
  private final class Chrome extends WebChromeClient {
    @Override public boolean onJsAlert(WebView v,String url,String message,JsResult result){new AlertDialog.Builder(MainActivity.this).setMessage(message).setPositiveButton("OK",(d,w)->result.confirm()).setOnCancelListener(d->result.cancel()).show();return true;}
    @Override public boolean onJsConfirm(WebView v,String url,String message,JsResult result){new AlertDialog.Builder(MainActivity.this).setMessage(message).setPositiveButton("Да",(d,w)->result.confirm()).setNegativeButton("Отмена",(d,w)->result.cancel()).setOnCancelListener(d->result.cancel()).show();return true;}
    @Override public boolean onShowFileChooser(WebView v,ValueCallback<Uri[]> callback,FileChooserParams params){
      if(picker!=null){callback.onReceiveValue(null);return true;}picker=callback;
      Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/json").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      try{startActivityForResult(i,PICK_JSON);}catch(ActivityNotFoundException e){picker=null;callback.onReceiveValue(null);message("Не найдено приложение для выбора файла");}return true;
    }
  }
  private final class BackupBridge {
    @JavascriptInterface public void save(String json,String filename){
      if(json==null||filename==null||!filename.matches("sobralis-(backup|raw-recovery)-[0-9]{4}-[0-9]{2}-[0-9]{2}\\.json")){runOnUiThread(()->message("Не удалось подготовить копию"));return;}
      byte[] data=json.getBytes(StandardCharsets.UTF_8);if(data.length>MAX_BACKUP){runOnUiThread(()->message("Копия больше 3 МБ"));return;}
      runOnUiThread(()->{
        if(pendingBackup!=null){message("Сначала завершите сохранение копии");return;}
        pendingBackup=data;pendingRawRecovery=filename.startsWith("sobralis-raw-recovery-");
        Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/json").putExtra(Intent.EXTRA_TITLE,filename).addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        try{startActivityForResult(i,SAVE_JSON);}catch(ActivityNotFoundException e){pendingBackup=null;pendingRawRecovery=false;message("Не найдено приложение для сохранения файла");}
      });
    }
  }
  @Override protected void onActivityResult(int code,int result,Intent data){
    super.onActivityResult(code,result,data);
    if(code==PICK_JSON){ValueCallback<Uri[]> cb=picker;picker=null;if(cb!=null){Uri u=result==RESULT_OK&&data!=null?data.getData():null;cb.onReceiveValue(u!=null&&"content".equals(u.getScheme())?new Uri[]{u}:null);}return;}
    if(code==SAVE_JSON){byte[] bytes=pendingBackup;final boolean raw=pendingRawRecovery;pendingBackup=null;pendingRawRecovery=false;Uri uri=result==RESULT_OK&&data!=null?data.getData():null;
      if(bytes==null||uri==null||!"content".equals(uri.getScheme()))return;
      new Thread(()->{try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException();out.write(bytes);out.flush();runOnUiThread(()->message(raw?"Аварийный файл сохранён. Это не обычная копия; он не зашифрован.":"Копия сохранена. Она не зашифрована."));}catch(Exception e){runOnUiThread(()->message("Не удалось сохранить копию. Проверьте выбранное место."));}}).start();
    }
  }
  private void message(String msg){Toast.makeText(this,msg,Toast.LENGTH_LONG).show();}
  @Override public void onBackPressed(){
    if(onlineWeb!=null){String url=onlineWeb.getUrl();String path=url==null?"":Uri.parse(url).getEncodedPath();if(onlineWeb.canGoBack()&&path!=null&&!path.isEmpty()&&!"/".equals(path)&&!"/index.html".equals(path))onlineWeb.goBack();else closeOnline();return;}
    web.evaluateJavascript("(function(){if(document.querySelector('#modal-root .modal-overlay')){closeModal();return true}if(menu){toggleMenu();return true}if(view!=='home'){navigate('home');return true}return false})()", value->{if(!"true".equals(value))new AlertDialog.Builder(this).setMessage("Закрыть приложение?").setPositiveButton("Закрыть",(d,w)->finish()).setNegativeButton("Остаться",null).show();});
  }
  @Override protected void onDestroy(){if(inviteDialog!=null){inviteDialog.dismiss();inviteDialog=null;}if(picker!=null){picker.onReceiveValue(null);picker=null;}pendingBackup=null;disposeOnline();if(web!=null){web.removeJavascriptInterface("AndroidOnline");web.removeJavascriptInterface("AndroidBackup");web.destroy();}super.onDestroy();}
}
