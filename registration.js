'use strict';
(()=>{
  // Fragment is never sent to the server, nor persisted. Reload requires the email link again.
  const verifying=location.pathname==='/verify-email';
  let token=verifying&&/^#[A-Za-z0-9_-]{43}$/.test(location.hash)?location.hash.slice(1):null;
  if(location.hash)history.replaceState(null,'',location.pathname+location.search);
  const content=document.getElementById('content'),message=document.getElementById('auth-message');
  const setMessage=x=>{message.textContent=x};
  const make=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e};
  const validPath=x=>typeof x==='string'&&/^\/legal\/[a-zA-Z0-9/_-]+$/.test(x);
  let docs,verificationGeneration=0,navigationGeneration=0;
  async function request(path,body){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
    try{const r=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},...(body?{body:JSON.stringify(body)}:{}),signal:controller.signal});
      let data={};try{data=await r.json()}catch{}if(!r.ok){const e=Error('request failed');e.status=r.status;e.code=data.error;throw e}return data;
    }finally{clearTimeout(timer)}
  }
  function documents(container){
    for(const [key,name,prefix] of [['dataConsent','согласием на обработку персональных данных','Я ознакомился и согласен с'],['terms','условиями использования','Я ознакомился и согласен с']]){
      const label=make('label');label.className='check';const check=make('input');check.type='checkbox';check.required=true;check.name=key;
      const span=make('span',prefix+' '),link=make('a',name);link.href=docs[key].url;link.target='_blank';link.rel='noopener noreferrer';span.append(link,document.createTextNode(` (версия ${docs[key].version}).`));label.append(check,span);container.append(label);
    }
  }
  function field(form,name,title,type,options={}){
    const label=make('label',title),input=make('input');input.name=name;input.type=type;input.required=true;
    if(options.max)input.maxLength=options.max;if(options.min)input.minLength=options.min;if(options.autocomplete)input.autocomplete=options.autocomplete;
    label.append(input);form.append(label);return input;
  }
  function status(e){if(e.status===429)return 'Слишком много запросов. Попробуйте позже.';if(e.status===503)return 'Регистрация временно недоступна. Попробуйте позже.';return 'Не удалось подтвердить результат из-за ошибки связи. Проверьте почту или попробуйте позже.'}
  async function loadConfig(){const x=await request('/api/auth/registration-config');if(x.enabled!==true)return null;
    const d=x.documents;if(!d||!['dataConsent','terms'].every(k=>d[k]&&validPath(d[k].url)&&typeof d[k].version==='string'&&d[k].version.length>0&&d[k].version.length<=80))throw Error('invalid configuration');return d}
  function showRegistration(){
    content.replaceChildren(make('h1','Создать аккаунт'),make('p','Введите имя и почту. Пароль вы зададите после подтверждения адреса.'));
    const form=make('form');form.noValidate=false;const name=field(form,'displayName','Как вас называть','text',{max:120,autocomplete:'name'}),email=field(form,'email','Электронная почта','email',{max:254,autocomplete:'email'});documents(form);
    const button=make('button','Получить письмо');button.type='submit';form.append(button);content.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;button.disabled=true;setMessage('Отправляем запрос…');try{
      await request('/api/auth/register',{email:email.value,displayName:name.value,dataConsentAccepted:form.elements.dataConsent.checked,termsAccepted:form.elements.terms.checked});
      setMessage('Если для этого адреса можно отправить письмо, оно придёт с дальнейшими инструкциями. Проверьте также папку «Спам». Приглашение в компанию после входа нужно открыть снова.');
    }catch(err){setMessage(status(err))}finally{button.disabled=false}});
    const details=make('details'),summary=make('summary','Письмо не пришло?'),hint=make('p','Повторное письмо можно запросить позже. Ответ одинаков для существующих и несуществующих адресов.');details.append(summary,hint);
    const resend=make('form'),mail=field(resend,'email','Электронная почта','email',{max:254,autocomplete:'email'}),send=make('button','Запросить письмо ещё раз');send.type='submit';resend.append(send);details.append(resend);content.append(details);
    resend.addEventListener('submit',async e=>{e.preventDefault();if(!resend.reportValidity())return;send.disabled=true;setMessage('Отправляем запрос…');try{await request('/api/auth/resend-verification',{email:mail.value});setMessage('Если повторное письмо доступно для этого адреса, оно будет отправлено. Проверьте почту и папку «Спам».')}catch(err){setMessage(status(err))}finally{send.disabled=false}});
  }
  function showVerification(){
    const generation=++verificationGeneration,currentToken=token;
    setMessage('');content.replaceChildren(make('h1','Подтвердить почту'));
    if(!token){content.append(make('p','Ссылка недействительна или уже убрана из адреса. Откройте ссылку из письма ещё раз; если срок вышел, запросите новое письмо.'));const link=make('a','Запросить письмо');link.href='/registration.html';content.append(link);return}
    content.append(make('p','Придумайте пароль и подтвердите согласие с документами. Ссылка одноразовая.'));
    const form=make('form'),password=field(form,'password','Новый пароль — от 12 символов','password',{min:12,max:128,autocomplete:'new-password'}),confirm=field(form,'confirm','Повторите пароль','password',{min:12,max:128,autocomplete:'new-password'});documents(form);
    const button=make('button','Подтвердить и сохранить пароль');button.type='submit';form.append(button);content.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;if(password.value!==confirm.value){setMessage('Пароли не совпадают. Проверьте ввод.');return}button.disabled=true;setMessage('Подтверждаем…');try{
      await request('/api/auth/verify-email',{token:currentToken,password:password.value,dataConsentAccepted:form.elements.dataConsent.checked,termsAccepted:form.elements.terms.checked,dataConsentVersion:docs.dataConsent.version,termsVersion:docs.terms.version});
      if(generation!==verificationGeneration)return;token=null;form.remove();setMessage('Почта подтверждена. Теперь можно войти с выбранным паролем и снова открыть приглашение.');
    }catch(err){if(generation!==verificationGeneration)return;if(err.code==='DOCUMENT_VERSION_CHANGED'){setMessage('Документы изменились. Откройте ссылку из письма заново и ознакомьтесь с новыми версиями.');button.disabled=true;button.dataset.locked='true';password.value='';confirm.value='';return}
      if(err.code==='INVALID_OR_EXPIRED_TOKEN'){token=null;form.remove();setMessage('Ссылка истекла или уже использована. Если аккаунт подтверждён, попробуйте войти; иначе запросите новое письмо.');return}
      if(!err.status||err.status>=500){password.value='';confirm.value='';token=null;form.remove();setMessage('Не удалось узнать результат. Возможно, почта уже подтверждена: попробуйте войти. Если вход не работает, запросите новое письмо.');return}
      setMessage(status(err));
    }finally{if(form.isConnected&&erroneous(button))button.disabled=false}});
  }
  async function refreshPage(){
    const generation=++navigationGeneration;verificationGeneration++;docs=undefined;setMessage('');content.replaceChildren(make('h1','Загружаем…'));
    try{const next=await loadConfig();if(generation!==navigationGeneration)return;docs=next;if(!docs){content.replaceChildren(make('h1','Регистрация пока недоступна'),make('p','Создание новых аккаунтов сейчас отключено.'));return}if(verifying)showVerification();else showRegistration()}
    catch{if(generation===navigationGeneration)content.replaceChildren(make('h1','Не удалось загрузить регистрацию'),make('p','Проверьте подключение и откройте страницу снова. Для подтверждения адреса откройте ссылку из письма заново.'))}
  }
  window.addEventListener('hashchange',()=>{if(!verifying)return;token=/^#[A-Za-z0-9_-]{43}$/.test(location.hash)?location.hash.slice(1):null;if(location.hash)history.replaceState(null,'',location.pathname+location.search);void refreshPage()});
  function erroneous(button){return button.dataset.locked!=='true'}
  void refreshPage();
})();
