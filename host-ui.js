'use strict';
// Host consent is a separate agreement. Names and descriptions always enter
// the DOM as text, never HTML. All requests remain scoped and server-authorized.
window.createHostPanel=({state,api,node,notice,eventCurrent,eventTime,refreshEvent})=>{
 const panel=node('section',null,'event-block host-panel');panel.id='host-panel';let serial=0;
 function clear(){serial++;panel.replaceChildren()}
 function current(id,g,s){return eventCurrent(id,g)&&serial===s&&!!state.user}
 async function tripMembers(id){let cursor=null,all=[],seen=new Set();for(let page=0;page<100;page++){
   const r=await api(`/api/trips/${id}/members`+(cursor?`?cursor=${encodeURIComponent(cursor)}`:''));all.push(...r.members);
   if(!r.nextCursor)return all;if(seen.has(r.nextCursor))throw Error('Не удалось загрузить участников поездки.');seen.add(r.nextCursor);cursor=r.nextCursor;
 }throw Error('Слишком много участников для выбора хозяина.')}
 function button(label,callback,cls='btn btn-soft'){const b=node('button',label,cls);b.type='button';b.addEventListener('click',callback);return b}
 async function load(id,g){const seq=++serial;panel.replaceChildren(node('h3','Хозяин и ночёвка 🏡'),node('p','Загружаем условия…'));
  try{
   const event=(await api(`/api/events/${id}`)).event;if(!current(id,g,seq))return;
   const [pending,change,members]=await Promise.all([api(`/api/events/${id}/host-proposal`),api(`/api/events/${id}/change-proposal`),event.trip_id?tripMembers(event.trip_id):Promise.resolve(state.members)]);
   if(!current(id,g,seq))return;render(event,pending.proposal,change.proposal,members,id,g,seq);
  }catch(e){if(!current(id,g,seq))return;panel.replaceChildren(node('h3','Хозяин и ночёвка 🏡'),node('p','Не удалось загрузить условия. Они не изменились.'),button('Повторить загрузку',()=>void load(id,g)));}
 }
 function render(event,proposal,change,members,id,g,seq){
  const name=x=>members.find(m=>m.id===x)?.display_name||'участник недоступен';
  const canEdit=state.eventRole==='owner'||state.eventRole==='editor',self=state.user.id;
  panel.replaceChildren(node('h3','Хозяин и ночёвка 🏡'));
  if(event.venue_type!=='home')panel.append(node('p','Дом для этой встречи не назначен. Предложение не означает согласие человека.'));
  else if(!event.host_active)panel.append(node('p','Условия хозяина не подтверждены или согласие отозвано. Старый адрес и условия ночёвки скрыты; нужно новое согласие.'));
  else {
    panel.append(node('p',`Дома у: ${name(event.host_id)}${event.host_id===self?' (вы)':''}.`));
    panel.append(node('p',event.overnight==='yes'?`Ночёвка возможна: мест ${event.overnight_capacity}.`:event.overnight==='no'?'Ночёвка не предусмотрена.':'Ночёвка пока не определена.'));
    if(event.location)panel.append(node('p',`Место: ${event.location}`));
  }
  const action=async(b,operation,success)=>{b.disabled=true;try{await operation();if(current(id,g,seq)){await load(id,g);if(eventCurrent(id,g))notice(success)}}catch(e){if(current(id,g,seq)){await load(id,g);if(eventCurrent(id,g))notice('Не удалось подтвердить действие. Состояние обновлено; проверьте его перед повтором.')}}finally{b.disabled=false}};
  if(change){
    const row=node('div',null,'host-proposal');row.id='event-change-proposal';row.append(node('h4','Предложено изменить встречу'),node('p',`Предложил(а): ${name(change.proposed_by)}. Сейчас: «${event.title}» · ${eventTime(event)} (${event.timezone}).`),node('p',`Предлагается: «${change.title}» · ${eventTime(change)} (${change.timezone}).`),node('p','До согласия хозяина встреча не изменится. Опросы и сообщения сохранятся; уведомления автоматически не отправляются.'));
    async function respond(b,decision){if(!confirm(decision==='accept'?'Согласиться принимать встречу с указанным названием и временем?':'Отклонить предложенное изменение встречи?'))return;b.disabled=true;let message=decision==='accept'?'Изменение принято хозяином. Сообщите участникам отдельно.':'Изменение отклонено; встреча не менялась.';
      try{try{await api(`/api/events/${id}/change-proposals/${change.id}/respond`,{method:'POST',body:{decision}})}catch{message='Не удалось подтвердить ответ. Обновляем встречу; проверьте её перед повтором.'}if(!current(id,g,seq))return;await refreshEvent(id,g);if(!current(id,g,seq))return;await load(id,g);if(eventCurrent(id,g))notice(message)}finally{b.disabled=false}}
    if(change.host_id===self){const yes=button('Согласиться с изменением',()=>void respond(yes,'accept'));const no=button('Отклонить изменение',()=>void respond(no,'decline'),'btn btn-plain');row.append(yes,no)}
    if(canEdit){const cancel=button('Отменить изменение',()=>{if(!confirm('Отменить предложение об изменении? Встреча останется прежней.'))return;void action(cancel,()=>api(`/api/events/${id}/change-proposals/${change.id}`,{method:'DELETE',body:{}}),'Предложение отменено; встреча не менялась.')},'btn btn-plain');row.append(cancel)}
    panel.append(row);
  }
  if(proposal){
    const row=node('div',null,'host-proposal');row.append(node('p',`Предложение: ${name(proposal.proposed_host)}. Пока человек не согласился, хозяин не меняется.`));
    if(proposal.proposed_host===self){
      const accept=button('Согласиться принимать',()=>{if(!confirm('Согласиться принимать встречу у себя? Прежний адрес места будет удалён, а условия ночёвки нужно будет указать заново.'))return;void action(accept,()=>api(`/api/events/${id}/host-proposals/${proposal.id}/respond`,{method:'POST',body:{decision:'accept',clearPreviousLocation:true}}),'Вы согласились принимать встречу. Укажите условия ночёвки.');});
      const decline=button('Отказаться',()=>void action(decline,()=>api(`/api/events/${id}/host-proposals/${proposal.id}/respond`,{method:'POST',body:{decision:'decline',clearPreviousLocation:false}}),'Предложение отклонено.'),'btn btn-plain');row.append(accept,decline);
    }
    if(canEdit){const cancel=button('Отменить предложение',()=>{if(!confirm('Отменить предложение хозяину?'))return;void action(cancel,()=>api(`/api/events/${id}/host-proposals/${proposal.id}`,{method:'DELETE',body:{}}),'Предложение отменено.')},'btn btn-plain');row.append(cancel)}
    panel.append(row);
  }
  if(event.venue_type==='home'&&event.host_active&&event.host_id===self){
    const form=node('form',null,'online-form compact host-conditions');const l=node('label','Ночёвка');const select=node('select');select.name='overnight';
    for(const [value,text] of [['undecided','Пока не знаю'],['yes','Возможна'],['no','Нет']]){const o=node('option',text);o.value=value;select.append(o)}select.value=event.overnight;l.append(select);
    const capacityLabel=node('label','Количество мест');const capacity=node('input');capacity.type='number';capacity.name='capacity';capacity.min='1';capacity.max='99';capacity.value=event.overnight_capacity||'';capacityLabel.append(capacity);
    function updateCapacity(){capacityLabel.hidden=select.value!=='yes';capacity.required=select.value==='yes'}select.addEventListener('change',updateCapacity);updateCapacity();
    const save=button('Сохранить условия',()=>{});save.type='submit';form.append(l,capacityLabel,save);
    form.addEventListener('submit',e=>{e.preventDefault();const n=select.value==='yes'?Number(capacity.value):null;if(n!==null&&(!Number.isInteger(n)||n<1||n>99)){notice('Укажите от 1 до 99 мест.');return}void action(save,()=>api(`/api/events/${id}/hosting`,{method:'PUT',body:{overnight:select.value,overnightCapacity:n}}),'Условия ночёвки сохранены.')});panel.append(form);
    const revoke=button('Я больше не принимаю',()=>{if(!confirm('Отозвать согласие принимать встречу? Адрес и условия ночёвки перестанут показываться участникам. Встреча не будет удалена.'))return;void action(revoke,()=>api(`/api/events/${id}/hosting`,{method:'DELETE',body:{}}),'Согласие отозвано; встреча сохранена.')},'btn btn-plain');panel.append(revoke);
  }
  if(canEdit){
    const candidates=members.filter(m=>!(event.venue_type==='home'&&event.host_active&&event.host_id===m.id));
    if(candidates.length){const f=node('form',null,'online-form compact host-propose');const l=node('label','Кого попросить принять');const select=node('select');select.name='host';select.required=true;
      const placeholder=node('option','Выберите участника');placeholder.value='';select.append(placeholder);for(const m of candidates){const o=node('option',m.display_name+(m.id===self?' (вы)':''));o.value=m.id;select.append(o)}l.append(select);const send=button('Предложить',()=>{});send.type='submit';f.append(l,send);
      f.addEventListener('submit',e=>{e.preventDefault();const who=select.value;if(!candidates.some(m=>m.id===who))return;if(proposal&&!confirm('Новое предложение отменит предыдущее. Продолжить?'))return;void action(send,()=>api(`/api/events/${id}/host-proposals`,{method:'POST',body:{hostId:who}}),'Предложение отправлено. Хозяин должен отдельно согласиться.')});panel.append(f);
    }
  }
  panel.append(node('p','Согласие можно отозвать. Выход из компании или поездки, потеря подтверждения почты или понижение роли отменяют прежнее согласие; повторное вступление его не восстанавливает.','online-note'));
 }
 return {panel,load,clear};
};
