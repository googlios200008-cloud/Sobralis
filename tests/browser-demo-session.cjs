// Requires an explicitly opted-in isolated demo. No cookies are allowed in these contexts.
const {chromium}=require('playwright'),assert=require('node:assert/strict');
if(process.env.ALLOW_BROWSER_DEMO_TEST!=='yes'||process.env.DB_NAME!=='sobralis_demo'||!process.env.DEMO_ORIGIN?.startsWith('https://'))throw Error('Explicit opt-in, disposable demo and HTTPS origin required');
const origin=process.env.DEMO_ORIGIN;
(async()=>{const browser=await chromium.launch({args:['--no-sandbox']});
async function setup(){const c=await browser.newContext();let sentCookies=0;
 await c.route('https://arena-test.invalid/**',r=>r.fulfill({status:200,contentType:'text/html',body:`<iframe src="${origin}/cloud.html?manual=1" style="width:1200px;height:900px"></iframe>`}));
 await c.route(`${origin}/**`,async r=>{const u=new URL(r.request().url()),h={...r.request().headers(),host:new URL(origin).host};if(h.cookie)sentCookies++;delete h.cookie;const response=await r.fetch({url:`http://127.0.0.1:4175${u.pathname}${u.search}`,headers:h});const headers={...response.headers()};delete headers['set-cookie'];await r.fulfill({response,headers})});
 const p=await c.newPage();await p.goto('https://arena-test.invalid/');return {c,p,f:p.frameLocator('iframe'),cookiesSent:()=>sentCookies};}
const a=await setup(),b=await setup();await a.f.locator('#demo-login:not([hidden])').waitFor();await a.f.locator('#demo-login').click();await a.f.locator('#group-content:not([hidden])').waitFor();assert.match(await a.f.locator('#account-name').innerText(),/Анна/);
await b.f.locator('input[name=email]').fill('max@example.test');await b.f.locator('input[name=password]').fill('DemoPassword2026!');await b.f.locator('#login-form button').click();await b.f.locator('#group-content:not([hidden])').waitFor();assert.match(await b.f.locator('#account-name').innerText(),/Макс/);
assert.equal(a.cookiesSent(),0);assert.equal(b.cookiesSent(),0);assert.equal((await a.c.cookies()).length,0);assert.equal((await b.c.cookies()).length,0);
await a.f.locator('#logout').click();await a.f.locator('#login:not([hidden])').waitFor();assert.equal(await b.f.locator('#workspace').isVisible(),true);
await b.p.reload();await b.f.locator('#login:not([hidden])').waitFor();await b.f.locator('#demo-login:not([hidden])').waitFor();
await a.c.close();await b.c.close();await browser.close();console.log('No-cookie embedded browser: two separate sessions, schedules, logout, reload and isolation passed');
})().catch(e=>{console.error(e);process.exit(1)});
