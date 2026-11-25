// Only bundled into the offline Android prototype. No network or production credentials.
(function(){
  const form=document.getElementById('login-form');
  if(form){form.hidden=true;const msg=document.createElement('p');msg.className='online-alert';
    if(window.AndroidOnline){msg.textContent='Совместный режим открыт отдельно от данных на устройстве. Это только синтетический тест: не вводите личные данные.';const button=document.createElement('button');button.type='button';button.className='btn btn-purple';button.textContent='Открыть тестовый совместный режим';button.addEventListener('click',()=>window.AndroidOnline.open());form.before(msg,button)}
    else {msg.textContent='В этой предварительной Android-сборке совместный режим ещё не подключён. Доступны только данные на этом устройстве.';form.before(msg)}
  }
  const intro=document.querySelector('#online-root .online-notice span');if(intro)intro.textContent='Данные Android-приложения хранятся отдельно от данных в браузере и не переносятся автоматически.';
  downloadBackup=function(){try{
    const text=JSON.stringify(createBackupEnvelope(state),null,2);
    if(new TextEncoder().encode(text).length>BACKUP_MAX_BYTES)throw Error('Копия больше 3 МБ');
    AndroidBackup.save(text,`sobralis-backup-${key(new Date())}.json`);
  }catch(err){toast('Не удалось создать копию: '+err.message)}};
})();
