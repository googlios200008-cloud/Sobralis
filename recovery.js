'use strict';
(()=>{
  const resetting=location.pathname==='/reset-password',content=document.getElementById('content'),message=document.getElementById('auth-message');
  let token=resetting&&/^#[A-Za-z0-9_-]{43}$/.test(location.hash)?location.hash.slice(1):null,generation=0;
  if(location.hash)history.replaceState(null,'',location.pathname+location.search);
  const setMessage=text=>{message.textContent=text},make=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n};
  async function request(path,body){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
    try{const r=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},...(body?{body:JSON.stringify(body)}:{}),signal:controller.signal});let data={};try{data=await r.json()}catch{}if(!r.ok){const e=Error('request failed');e.status=r.status;e.code=data.error;throw e}return data}finally{clearTimeout(timer)}}
  function input(form,name,title,type,{min,max,autocomplete}={}){const label=make('label',title),field=make('input');field.name=name;field.type=type;field.required=true;if(min)field.minLength=min;if(max)field.maxLength=max;if(autocomplete)field.autocomplete=autocomplete;label.append(field);form.append(label);return field}
  function requestForm(){content.replaceChildren(make('h1','Восстановить доступ'),make('p','Введите почту аккаунта. Если восстановление доступно, мы отправим одноразовую ссылку.'));
    const form=make('form'),email=input(form,'email','Электронная почта','email',{max:254,autocomplete:'email'}),button=make('button','Запросить письмо');button.type='submit';form.append(button);content.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;button.disabled=true;setMessage('Отправляем запрос…');try{await request('/api/auth/request-password-reset',{email:email.value});setMessage('Если для этого адреса восстановление доступно, письмо будет отправлено. Проверьте почту и папку «Спам».')}catch(err){setMessage(err.status===429?'Слишком много запросов. Попробуйте позже.':'Не удалось подтвердить результат. Проверьте почту или попробуйте позже.')}finally{button.disabled=false}});
  }
  function resetForm(g){const currentToken=token;content.replaceChildren(make('h1','Новый пароль'));if(!currentToken){content.append(make('p','Ссылка недействительна или уже убрана из адреса. Откройте письмо снова или запросите новую ссылку.'));const link=make('a','Запросить письмо');link.href='/recovery.html';content.append(link);return}
    content.append(make('p','Задайте новый пароль. После изменения все действующие сеансы этого аккаунта будут завершены. Данные аккаунта сохранятся.'));
    const form=make('form'),password=input(form,'password','Новый пароль — от 12 символов','password',{min:12,max:128,autocomplete:'new-password'}),confirm=input(form,'confirm','Повторите пароль','password',{min:12,max:128,autocomplete:'new-password'}),button=make('button','Сохранить новый пароль');button.type='submit';form.append(button);content.append(form);
    form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;if(password.value!==confirm.value){setMessage('Пароли не совпадают. Проверьте ввод.');return}button.disabled=true;setMessage('Сохраняем…');try{
      await request('/api/auth/reset-password',{token:currentToken,password:password.value});if(g!==generation)return;token=null;form.remove();setMessage('Пароль изменён. Войдите с новым паролем. Другие сеансы завершены.');
    }catch(err){if(g!==generation)return;if(err.code==='INVALID_OR_EXPIRED_TOKEN'){token=null;form.remove();setMessage('Ссылка истекла или уже использована. Попробуйте войти с новым паролем или запросите новое письмо.');return}
      if(!err.status||err.status>=500){token=null;form.remove();setMessage('Не удалось узнать результат. Возможно, пароль уже изменён: попробуйте войти с новым паролем. Если вход не работает, запросите новое письмо.');return}
      setMessage(err.status===429?'Слишком много запросов. Попробуйте позже.':'Не удалось выполнить запрос. Проверьте данные и попробуйте позже.');
    }finally{if(form.isConnected&&g===generation)button.disabled=false}});
  }
  async function refresh(){const g=++generation;setMessage('');content.replaceChildren(make('h1','Загружаем…'));try{const x=await request('/api/auth/recovery-config');if(g!==generation)return;if(x.enabled!==true){content.replaceChildren(make('h1','Восстановление пока недоступно'),make('p','Восстановление доступа сейчас отключено.'));return}if(resetting)resetForm(g);else requestForm()}catch{if(g===generation)content.replaceChildren(make('h1','Не удалось загрузить страницу'),make('p','Проверьте подключение и откройте страницу снова. Если у вас письмо, откройте ссылку из него ещё раз.'))}}
  window.addEventListener('hashchange',()=>{if(!resetting)return;token=/^#[A-Za-z0-9_-]{43}$/.test(location.hash)?location.hash.slice(1):null;if(location.hash)history.replaceState(null,'',location.pathname+location.search);void refresh()});
  void refresh();
})();
