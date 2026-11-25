package ru.sobralis.app;

public final class OnlinePolicyTest {
  private static void ok(boolean v){if(!v)throw new AssertionError();}
  public static void main(String[] args){
    for(String bad:new String[]{"", "http://a.example.test", "https://a.example.com", "https://test", "https://a.example.test/", "https://user@a.example.test", "https://a.example.test?x=1", "https://a.example.test#x", "https://A.example.test", "https://a.example.test:0", "https://a.example.test:443", "https://a.example.test:", "https://a.example.test:08443", "https://a.example.test:65536", "https://a..test", "https://-a.test", "https://127.0.0.1", "https://a.example.test.evil.test:bad"})ok(OnlinePolicy.fromOrigin(bad)==null);
    OnlinePolicy p=OnlinePolicy.fromOrigin("https://a.example.test:8443");ok(p!=null);
    for(String url:new String[]{"https://a.example.test:8443/", "https://a.example.test:8443/index.html#community-invite=abc", "https://a.example.test:8443/api/auth/login", "HTTPS://A.EXAMPLE.TEST:8443/"})ok(p.allows(url));
    for(String url:new String[]{"http://a.example.test:8443/", "https://evil.example.test:8443/", "https://a.example.test.evil.test:8443/", "https://a.example.test/", "https://a.example.test:443/", "https://a.example.test:8444/", "https://a.example.test:08443/", "https://a.example.test:/", "https://a.example.test@evil.test:8443/", "https://evil.test@a.example.test:8443/", "file:///index.html", "javascript:alert(1)", "data:text/html,abc"})ok(!p.allows(url));
    for(String url:new String[]{"https://a.example.test:8443/", "https://a.example.test:8443/index.html#trip-invite=abc", "https://a.example.test:8443/registration.html", "https://a.example.test:8443/verify-email#token", "https://a.example.test:8443/recovery.html", "https://a.example.test:8443/reset-password#token"})ok(p.allowsNavigation(url));
    for(String url:new String[]{"https://a.example.test:8443/api/auth/me", "https://a.example.test:8443/%69ndex.html", "https://a.example.test:8443/index.html/extra", "https://evil.test:8443/index.html"})ok(!p.allowsNavigation(url));
    String token="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for(String type:new String[]{"community-invite","trip-invite"}){
      String fragment=type+"="+token;
      ok(p.invitePath("https://a.example.test:8443/#"+fragment).equals("/#"+fragment));
      ok(p.invitePath("https://a.example.test:8443#"+fragment).equals("/#"+fragment));
      for(String bad:new String[]{"https://evil.test:8443/#"+fragment,"https://a.example.test/#"+fragment,
        "http://a.example.test:8443/#"+fragment,"https://user@a.example.test:8443/#"+fragment,
        "https://a.example.test:8443/path#"+fragment,"https://a.example.test:8443/?x=1#"+fragment,
        "https://a.example.test:8443/#"+fragment+"&trip-invite="+token,"https://a.example.test:8443/#"+type+"="+token+"A",
        "https://a.example.test:8443/#"+type+"=%41"+token.substring(1),"https://a.example.test:8443/#other="+token})ok(p.invitePath(bad)==null);
    }
    OnlinePolicy normal=OnlinePolicy.fromOrigin("https://a.example.test");ok(normal!=null&&normal.allows("https://a.example.test:443/index.html"));ok(!normal.allows("https://a.example.test:444/index.html"));
    System.out.println("Android synthetic online origin, navigation and invitation policy passed");
  }
}
