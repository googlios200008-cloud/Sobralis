// Local-only household shortcuts. Not an account, authorization or delegation.
(() => {
  'use strict';
  icons.family='<path d="M3 12l9-8 9 8"/><path d="M5 10v10h14V10M9 20v-5h6v5"/>';
  const previousSidebar=sidebar;
  sidebar=function(){return previousSidebar().replace('</nav><div class="side-heading">',`${nav('family','family','Семья')}</nav><div class="side-heading">`)};
  function familyIds(){const ids=group().familyPeople;return Array.isArray(ids)?ids.filter(id=>typeof id==='string'&&group().people.some(p=>p.id===id)):[]}
  function familyView(){
    const g=group(),ids=familyIds();
    const rows=ids.map(id=>{const i=g.people.findIndex(p=>p.id===id),p=g.people[i];return `<li class="family-person"><span class="family-avatar" aria-hidden="true">💜</span><span><strong>${esc(p.name)}</strong><small>Отдельный график</small></span><button type="button" class="btn btn-soft" data-click="familySchedule" data-a="${esc(i)}">Открыть график</button><button type="button" class="family-remove" data-click="familyRemove" data-a="${esc(i)}" aria-label="Убрать ${esc(p.name)} из семьи">Убрать</button></li>`}).join('');
    const choices=g.people.map((p,i)=>`<option value="${i}">${esc(p.name)}</option>`).join('');
    return `${heading('Семья 💜','Графики близких на одном устройстве — отдельно для каждого.')}
      <div class="family-layout"><div class="card family-card"><div class="family-kicker">МОЯ СЕМЬЯ · ${esc(g.name)}</div><h2>Кого планируем вместе?</h2><p>Откройте график нужного человека и отметьте его дни. Изменения не затрагивают графики остальных.</p>
      ${rows?`<ul class="family-list">${rows}</ul>`:'<div class="family-empty">Добавьте себя и близкого человека из списка или создайте нового участника ниже.</div>'}
      <form class="family-form" data-submit="familyAddExisting"><label for="family-existing">Выбрать из участников компании</label><div class="family-form-row"><select name="index" id="family-existing">${choices}</select><button class="btn btn-purple" type="submit">Добавить в семью</button></div></form>
      <form class="family-form" data-submit="familyAddNew"><label for="family-new">Или добавить нового человека</label><div class="family-form-row"><input id="family-new" name="name" maxlength="35" autocomplete="off" required placeholder="Имя, например Маша"><button class="btn btn-soft" type="submit">Создать участника</button></div><p>Новый человек также появится в участниках этой компании.</p></form></div>
      <aside class="card family-privacy"><h2>Бережно к личному 🛡️</h2><p>Добавляйте близкого и отмечайте его график только с его ведома и разрешения. Здесь нет подтверждения согласия или отдельной учётной записи.</p><p><strong>Только на этом устройстве:</strong> семья не синхронизируется с сервером, приглашения не отправляются. Копия данных не зашифрована.</p><p>Кнопка «Убрать» снимает только семейную отметку — человек и его график остаются в компании.</p></aside></div>`;
  }
  const previousRender=render;
  render=function(){previousRender();if(view==='family'){const content=document.querySelector('#app .content');if(content)content.innerHTML=familyView()}};
  function memberFromIndex(i){if(!Number.isInteger(i)||i<0||i>=group().people.length)return null;return group().people[i]}
  window.familySchedule=function(i){const p=memberFromIndex(i);if(!p||!familyIds().includes(p.id))return;selectedPerson=p.id;scheduleMode='person';navigate('schedule')};
  window.familyAddExisting=function(e){e.preventDefault();const raw=new FormData(e.target).get('index');if(typeof raw!=='string'||!/^\d+$/.test(raw))return;const p=memberFromIndex(Number(raw));if(!p)return;const previous=group().familyPeople,ids=familyIds();if(ids.includes(p.id)){toast('Этот человек уже в семье');return}group().familyPeople=[...ids,p.id];try{save()}catch{if(previous===undefined)delete group().familyPeople;else group().familyPeople=previous;toast('Не удалось сохранить: проверьте доступ к хранилищу');return}render();toast('Добавлено в семью 💜')};
  window.familyAddNew=function(e){e.preventDefault();const name=String(new FormData(e.target).get('name')||'').trim();if(!name||name.length>35){toast('Введите имя до 35 символов');return}const g=group(),oldFamily=g.familyPeople,oldChosen=chosenPeople,ids=familyIds(),p={id:uid(),name};g.people.push(p);g.schedule[p.id]={};g.familyPeople=[...ids,p.id];chosenPeople=[...(chosenPeople||[]),p.id];try{save()}catch{g.people.pop();delete g.schedule[p.id];if(oldFamily===undefined)delete g.familyPeople;else g.familyPeople=oldFamily;chosenPeople=oldChosen;toast('Не удалось сохранить: проверьте доступ к хранилищу');return}render();toast('Участник добавлен. Теперь можно заполнить его график 💜')};
  window.familyRemove=function(i){const p=memberFromIndex(i);if(!p)return;const old=group().familyPeople;group().familyPeople=familyIds().filter(id=>id!==p.id);try{save()}catch{group().familyPeople=old;toast('Не удалось сохранить изменения');return}render();toast('Семейная отметка снята; график сохранён')};
  window.familyView=familyView;
  render();
})();
