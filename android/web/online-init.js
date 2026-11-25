// Synthetic connected Android prototype: UI adaptation only, not a security boundary.
(function(){
  if(!document.getElementById('android-online-style')){
    const style=document.createElement('style');style.id='android-online-style';
    style.textContent='.sidebar .nav button:not([onclick*=online]),.sidebar .nav-label:not(.online-nav-label),.sidebar .side-heading,.sidebar .group-button,.sidebar .side-bottom{display:none!important}';
    document.head.appendChild(style);
  }
  const note=document.querySelector('#online-root .online-notice span');
  if(note)note.textContent='Это отдельное онлайн-пространство. Данные на устройстве не переносятся автоматически. Для возврата нажмите кнопку сверху.';
  if(typeof navigate==='function')navigate('online');
})();
