import React, {useEffect, useMemo, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {
  ArrowLeft, Bell, Bookmark, Building2, Check, ChevronRight,
  MapPin, MessageCircle, Search, Share2, SlidersHorizontal, X
} from 'lucide-react';
import './styles.css';

type Listing = {
  code:string; operation:string; propertyType:string; address:string;
  priceAmount:string; priceCurrency:string; details:Record<string,number>;
  highlightedFeatures:string[]; description:string; notes:string[];
  images:string[]; photoCount:number; sourceUrl:string; neighborhoods:string[]; listingToken:string;
};
type Catalog = {count:number; operations:Record<string,number>; neighborhoods:string[]; items:Listing[]};
type PublicConfig = {brandName:string; brandTagline:string; botUsername:string};
type Filters = {
  operation:string; query:string; neighborhoods:string[]; propertyTypes:string[];
  rooms:number|null; maxBudget:string; budgetCurrency:string;
};
type SavedSearch = {id:string; label:string; criteria:Record<string,unknown>; notify:boolean; createdAt:string};

const tg = window.Telegram?.WebApp;
const initData = tg?.initData || '';
const startParam = String(tg?.initDataUnsafe?.start_param || '');
const launchParams = new URLSearchParams(window.location.search);
const urlTracking = launchParams.get('trk') || '';
const trackingToken = urlTracking || (startParam.startsWith('trk_') ? startParam.slice(4) : '');
const requestedListing = launchParams.get('listing') || '';
const requestedSavedSearch = launchParams.get('saved') || '';

function api<T>(path:string, options?:RequestInit):Promise<T>{
  const controller=new AbortController();
  const timer=window.setTimeout(()=>controller.abort(),10000);
  return fetch(path,{
    ...options,
    signal:controller.signal,
    headers:{'content-type':'application/json',...(options?.headers||{})}
  }).then(async r=>{
    if(!r.ok){
      let message='Ошибка';
      try{ const j=await r.json(); message=j.detail||message; }catch{}
      throw new Error(message);
    }
    return r.json();
  }).catch(err=>{
    if(err?.name==='AbortError') throw new Error('Сервер не ответил. Попробуйте ещё раз.');
    throw err;
  }).finally(()=>window.clearTimeout(timer));
}

function fmtPrice(item:Listing){
  const n=Number(item.priceAmount);
  const value=Number.isFinite(n)?new Intl.NumberFormat('ru-RU',{maximumFractionDigits:0}).format(n):item.priceAmount;
  return `${item.priceCurrency==='USD'?'US$':item.priceCurrency||''} ${value}`.trim();
}
function spec(item:Listing){
  const d=item.details||{};
  const rows:string[]=[];
  const area=d.totalAreaM2||d.coveredAreaM2;
  if(area) rows.push(`${area} м²`);
  if(d.rooms) rows.push(`${d.rooms} комн.`);
  if(d.bedrooms) rows.push(`${d.bedrooms} спальн.`);
  return rows.join(' · ');
}
function filtersToCriteria(f:Filters){
  return {
    operation:f.operation||undefined,
    query:f.query.trim()||undefined,
    neighborhoods:f.neighborhoods,
    propertyTypes:f.propertyTypes,
    rooms:f.rooms||undefined,
    maxBudget:f.maxBudget?Number(f.maxBudget):undefined,
    budgetCurrency:f.maxBudget?f.budgetCurrency:undefined,
  };
}
function criteriaToFilters(criteria:Record<string,unknown>):Filters{
  const neighborhoods=Array.isArray(criteria.neighborhoods)?criteria.neighborhoods.map(String):[];
  const propertyTypes=Array.isArray(criteria.propertyTypes)?criteria.propertyTypes.map(String):[];
  return {
    operation:typeof criteria.operation==='string'?criteria.operation:'',
    query:typeof criteria.query==='string'?criteria.query:'',
    neighborhoods,
    propertyTypes,
    rooms:criteria.rooms?Number(criteria.rooms):null,
    maxBudget:criteria.maxBudget?String(criteria.maxBudget):'',
    budgetCurrency:typeof criteria.budgetCurrency==='string'?criteria.budgetCurrency:'USD',
  };
}
function activeFilterCount(f:Filters){
  return (f.operation?1:0)+(f.query?1:0)+f.neighborhoods.length+f.propertyTypes.length+(f.rooms?1:0)+(f.maxBudget?1:0);
}
function canSaveSearch(f:Filters){
  return Boolean(f.query.trim()||f.neighborhoods.length||f.propertyTypes.length||f.rooms||f.maxBudget);
}
function normalizedSearch(value:string){
  return value.toLowerCase().replace(/ё/g,'е').replace(/[^a-záéíóúñüа-я0-9]+/gi,' ').trim();
}
function listingKey(item:Listing){
  return item.listingToken||item.code;
}
async function ensureWriteAccess(){
  if(!tg) return false;
  if(tg.initDataUnsafe?.user?.allows_write_to_pm) return true;
  if(typeof tg.requestWriteAccess!=='function') return true;
  return await new Promise<boolean>(resolve=>{
    try{ tg.requestWriteAccess((allowed:boolean)=>resolve(Boolean(allowed))); }
    catch{ resolve(false); }
  });
}

const DEFAULT_FILTERS:Filters={
  operation:'',query:'',neighborhoods:[],propertyTypes:[],rooms:null,maxBudget:'',budgetCurrency:'USD'
};
const DEFAULT_CONFIG:PublicConfig={brandName:'Каталог',brandTagline:'Недвижимость',botUsername:''};
function brandInitials(name:string){
  const parts=name.trim().split(/\s+/).filter(Boolean);
  return (parts.length>1?parts.slice(0,2).map(x=>x[0]).join(''):name.slice(0,2)).toUpperCase()||'RE';
}

function App(){
  const [config,setConfig]=useState<PublicConfig>(DEFAULT_CONFIG);
  const [catalog,setCatalog]=useState<Catalog|null>(null);
  const [loadError,setLoadError]=useState('');
  const [filters,setFilters]=useState<Filters>(DEFAULT_FILTERS);
  const [selected,setSelected]=useState<Listing|null>(null);
  const [filtersOpen,setFiltersOpen]=useState(false);
  const [saveOpen,setSaveOpen]=useState(false);
  const [savedOpen,setSavedOpen]=useState(false);
  const [notify,setNotify]=useState(false);
  const [saved,setSaved]=useState<SavedSearch[]>([]);
  const [toast,setToast]=useState('');
  const [busy,setBusy]=useState(false);
  const searchStarted=useRef(false);

  useEffect(()=>{
    if(tg){
      try{
        tg.ready(); tg.expand();
        tg.setHeaderColor?.('bg_color');
        tg.setBackgroundColor?.('bg_color');
        tg.setBottomBarColor?.('bg_color');
        tg.enableVerticalSwipes?.();
      }catch{}
    }
    api<PublicConfig>('/api/v1/config').then(data=>{
      setConfig(data);
      document.title=data.brandTagline?(data.brandName+' · '+data.brandTagline):data.brandName;
      document.querySelector('meta[name="description"]')?.setAttribute('content','Каталог недвижимости · '+data.brandName);
    }).catch(()=>{});
    api<Catalog>('/api/v1/catalog').then(data=>{
      setLoadError('');
      setCatalog(data);
      if(initData) event('catalog_opened');
      if(requestedListing){
        const item=data.items.find(x=>listingKey(x)===requestedListing||x.code===requestedListing);
        if(item) openListing(item);
        else{
          api<Listing>(`/api/v1/catalog/${encodeURIComponent(requestedListing)}`)
            .then(full=>{setSelected(full);event('listing_opened',full);})
            .catch(()=>showToast('Этот объект больше не доступен'));
        }
      }else if(requestedSavedSearch&&initData){
        restoreSavedSearch(requestedSavedSearch);
      }
    }).catch(err=>{
      const message=err?.message||'Не удалось загрузить каталог';
      setLoadError(message);
      showToast(message);
    });
  },[]);

  useEffect(()=>{
    if(!tg?.BackButton) return;
    const goBack=()=>{
      if(selected) setSelected(null);
      else if(filtersOpen) setFiltersOpen(false);
      else if(saveOpen) setSaveOpen(false);
      else if(savedOpen) setSavedOpen(false);
    };
    if(selected||filtersOpen||saveOpen||savedOpen){tg.BackButton.show(); tg.BackButton.onClick(goBack);}
    else tg.BackButton.hide();
    return ()=>{try{tg.BackButton.offClick(goBack);}catch{}};
  },[selected,filtersOpen,saveOpen,savedOpen]);

  useEffect(()=>{
    if(savedOpen&&initData) loadSaved();
  },[savedOpen]);

  function showToast(message:string){
    setToast(message);
    setTimeout(()=>setToast(''),2400);
  }
  function haptic(kind:'light'|'medium'|'success'='light'){
    try{
      if(kind==='success') tg?.HapticFeedback?.notificationOccurred('success');
      else tg?.HapticFeedback?.impactOccurred(kind);
    }catch{}
  }
  async function event(name:string, listing?:Listing, properties:Record<string,unknown>={}){
    if(!initData) return;
    try{
      await api('/api/v1/events',{method:'POST',body:JSON.stringify({
        init_data:initData,event_name:name,listing_code:listing?listingKey(listing):undefined,properties,
        link_token:trackingToken||undefined
      })});
    }catch{}
  }
  function touchSearch(){
    if(!searchStarted.current){
      searchStarted.current=true;
      event('search_started');
    }
  }
  function update(patch:Partial<Filters>){
    touchSearch();
    setFilters(prev=>({...prev,...patch}));
  }
  function toggleNeighborhood(name:string){
    touchSearch();
    setFilters(prev=>({...prev,neighborhoods:prev.neighborhoods.includes(name)
      ?prev.neighborhoods.filter(x=>x!==name):[...prev.neighborhoods,name]}));
  }
  function toggleType(name:string){
    touchSearch();
    setFilters(prev=>({...prev,propertyTypes:prev.propertyTypes.includes(name)
      ?prev.propertyTypes.filter(x=>x!==name):[...prev.propertyTypes,name]}));
  }

  const results=useMemo(()=>{
    if(!catalog) return [];
    const q=normalizedSearch(filters.query);
    const queryTokens=q.split(/\s+/).filter(x=>x.length>=3&&!['квартира','квартиру','дом','ищу','нужна'].includes(x));
    return catalog.items.filter(item=>{
      if(filters.operation&&item.operation!==filters.operation) return false;
      if(filters.neighborhoods.length&&!filters.neighborhoods.some(x=>item.neighborhoods.includes(x))) return false;
      if(filters.propertyTypes.length&&!filters.propertyTypes.includes(item.propertyType)) return false;
      if(filters.rooms&&Number(item.details?.rooms||0)!==filters.rooms) return false;
      if(filters.maxBudget){
        if(item.priceCurrency!==filters.budgetCurrency) return false;
        if(Number(item.priceAmount||0)>Number(filters.maxBudget)) return false;
      }
      if(queryTokens.length){
        const hay=normalizedSearch([item.address,item.description,...item.highlightedFeatures,...item.neighborhoods].join(' '));
        if(!queryTokens.some(token=>hay.includes(token))) return false;
      }
      return true;
    });
  },[catalog,filters]);

  const propertyTypes=useMemo(()=>catalog?Array.from(new Set(catalog.items.map(x=>x.propertyType).filter(Boolean))).sort():[],[catalog]);
  const quickHoods=['palermo','belgrano','nunez','recoleta','colegiales'].filter(x=>catalog?.neighborhoods.includes(x));

  async function openListing(item:Listing){
    haptic();
    // Open immediately with the lightweight card data, then hydrate the full
    // gallery/description in the background. This keeps Telegram navigation instant.
    setSelected(item);
    event('listing_opened',item);
    try{
      const key=listingKey(item);
      const full=await api<Listing>(`/api/v1/catalog/${encodeURIComponent(key)}`);
      setSelected(current=>current&&listingKey(current)===key?full:current);
    }catch(err:any){
      showToast(err.message||'Не удалось загрузить детали');
    }
  }
  async function listingAction(action:string){
    if(!selected) return;
    if(!initData){showToast('Откройте каталог внутри Telegram');return;}
    setBusy(true);
    try{
      const res=await api<{telegram_url:string;share_url?:string;prepared_message_id?:string}>('/api/v1/actions',{
        method:'POST',body:JSON.stringify({
          init_data:initData,listing_code:listingKey(selected),action,link_token:trackingToken||undefined
        })
      });
      if(action==='share'&&res.prepared_message_id&&typeof tg?.shareMessage==='function'){
        const listingAtShare=selected;
        tg.shareMessage(res.prepared_message_id,(sent:boolean)=>{
          if(sent){
            haptic('success');
            event('share_sent',listingAtShare,{via:'prepared_message'});
          }
        });
        return;
      }
      haptic('success');
      const destination=action==='share'&&res.share_url?res.share_url:res.telegram_url;
      if(tg?.openTelegramLink) tg.openTelegramLink(destination);
      else window.location.href=destination;
    }catch(err:any){showToast(err.message||'Не удалось открыть чат');}
    finally{setBusy(false);}
  }
  async function saveSearch(){
    if(!initData){showToast('Сохранение доступно внутри Telegram');return;}
    if(!canSaveSearch(filters)){showToast('Добавьте район, тип, комнаты, бюджет или поисковый запрос');return;}
    setBusy(true);
    try{
      if(notify){
        const allowed=await ensureWriteAccess();
        if(!allowed){
          showToast('Разрешите сообщения от бота, чтобы получать новые варианты');
          return;
        }
      }
      const res=await api<{label:string;matches_now:number}>('/api/v1/saved-searches',{
        method:'POST',
        body:JSON.stringify({
          init_data:initData,criteria:filtersToCriteria(filters),notify,link_token:trackingToken||undefined
        })
      });
      setSaveOpen(false);
      haptic('success');
      showToast(notify?`Поиск сохранён · сейчас ${res.matches_now}`:'Поиск сохранён');
    }catch(err:any){showToast(err.message||'Не удалось сохранить');}
    finally{setBusy(false);}
  }
  async function restoreSavedSearch(id:string){
    try{
      const res=await api<{items:SavedSearch[]}>(`/api/v1/saved-searches?init_data=${encodeURIComponent(initData)}`);
      setSaved(res.items);
      const found=res.items.find(item=>item.id===id);
      if(found){
        setFilters(criteriaToFilters(found.criteria));
        searchStarted.current=true;
        showToast('Ваш сохранённый поиск');
      }
    }catch(err:any){
      showToast(err.message||'Не удалось открыть сохранённый поиск');
    }
  }
  async function loadSaved(){
    try{
      const res=await api<{items:SavedSearch[]}>(`/api/v1/saved-searches?init_data=${encodeURIComponent(initData)}`);
      setSaved(res.items);
    }catch(err:any){showToast(err.message||'Не удалось загрузить');}
  }
  async function removeSaved(id:string){
    try{
      await api(`/api/v1/saved-searches/${id}?init_data=${encodeURIComponent(initData)}`,{method:'DELETE'});
      setSaved(x=>x.filter(s=>s.id!==id)); haptic('success');
    }catch(err:any){showToast(err.message||'Не удалось удалить');}
  }

  if(!catalog&&loadError){
    return <div className="loading loadError">
      <div className="emptyIcon"><X size={26}/></div>
      <strong>Не удалось открыть каталог</strong>
      <span>{loadError}</span>
      <button className="primary" onClick={()=>window.location.reload()}>Повторить</button>
    </div>;
  }

  if(!catalog){
    return <div className="loading"><div className="spinner"/><span>Загружаем каталог {config.brandName}</span></div>;
  }

  if(selected){
    return <ListingDetail item={selected} busy={busy} brandName={config.brandName} onBack={()=>setSelected(null)}
      onAction={listingAction} onGallery={()=>event('gallery_opened',selected)} />;
  }

  return <div className="app">
    <header className="topbar">
      <div className="brand">
        <div className="brandMark">{brandInitials(config.brandName)}</div>
        <div><strong>{config.brandName}</strong><span>{config.brandTagline||'Недвижимость'}</span></div>
      </div>
      {initData&&<button className="iconBtn" onClick={()=>setSavedOpen(true)} aria-label="Мои поиски"><Bookmark size={20}/></button>}
    </header>

    <main className="content">
      <section className="intro">
        <div className="kicker">АКТУАЛЬНЫЙ КАТАЛОГ</div>
        <h1>Найдите свой вариант</h1>
        <p>{catalog.count} объектов · данные обновляются автоматически</p>
      </section>

      <div className="segment">
        {[['','Все'],['Venta','Купить'],['Alquiler','Арендовать']].map(([value,label])=>
          <button key={value} className={filters.operation===value?'active':''} onClick={()=>update({operation:value})}>{label}</button>
        )}
      </div>

      <div className="searchBox">
        <Search size={20}/>
        <input value={filters.query} onChange={e=>update({query:e.target.value})}
          placeholder="Район, город, адрес или код объекта" aria-label="Поиск"/>
        {filters.query&&<button onClick={()=>update({query:''})} aria-label="Очистить"><X size={18}/></button>}
      </div>

      <div className="quickRow">
        {quickHoods.map(hood=><button key={hood} className={filters.neighborhoods.includes(hood)?'chip active':'chip'}
          onClick={()=>toggleNeighborhood(hood)}>{prettyHood(hood)}</button>)}
        <button className={activeFilterCount(filters)>0?'chip filterChip active':'chip filterChip'} onClick={()=>setFiltersOpen(true)}>
          <SlidersHorizontal size={15}/> Фильтры {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
        </button>
      </div>

      <div className="resultHeader">
        <div><strong>{results.length}</strong><span> {plural(results.length,'объект','объекта','объектов')}</span></div>
        {activeFilterCount(filters)>0&&<button className="textBtn" onClick={()=>{setFilters(DEFAULT_FILTERS);searchStarted.current=false}}>Сбросить</button>}
      </div>

      <section className="cards">
        {results.map(item=><ListingCard key={item.code+item.sourceUrl} item={item} onOpen={()=>openListing(item)}/>)}
        {!results.length&&<div className="emptyState">
          <div className="emptyIcon"><Search size={26}/></div>
          <h3>Точного совпадения нет</h3>
          <p>{canSaveSearch(filters)
            ?'Сохраните этот поиск. Если подходящий объект появится, мы сможем сообщить вам в Telegram.'
            :'Добавьте район, тип объекта, комнаты, бюджет или поисковый запрос, чтобы сохранить поиск.'}</p>
          {canSaveSearch(filters)&&<button className="primary" onClick={()=>setSaveOpen(true)}><Bell size={18}/> Сохранить поиск</button>}
        </div>}
      </section>
    </main>

    {canSaveSearch(filters)&&results.length>0&&
      <div className="stickySave"><button onClick={()=>setSaveOpen(true)}><Bell size={18}/> Сохранить поиск <span>{results.length}</span></button></div>}

    {filtersOpen&&<FilterSheet filters={filters} propertyTypes={propertyTypes} neighborhoods={catalog.neighborhoods}
      count={results.length} onClose={()=>setFiltersOpen(false)} onUpdate={update} onToggleHood={toggleNeighborhood} onToggleType={toggleType}/>}

    {saveOpen&&<SaveSheet notify={notify} setNotify={setNotify} count={results.length} busy={busy}
      authenticated={!!initData} botUsername={config.botUsername} onClose={()=>setSaveOpen(false)} onSave={saveSearch}/>}

    {savedOpen&&<SavedSheet items={saved} onClose={()=>setSavedOpen(false)} onDelete={removeSaved}/>}

    {toast&&<div className="toast"><Check size={17}/>{toast}</div>}
  </div>;
}

function ListingCard({item,onOpen}:{item:Listing;onOpen:()=>void}){
  return <button className="listingCard" onClick={onOpen}>
    <div className="cover">
      {item.images?.[0]?<img src={item.images[0]} alt={item.address||item.code} loading="lazy"/>:<div className="noPhoto"><Building2/></div>}
      <span className="opBadge">{item.operation==='Venta'?'Продажа':'Аренда'}</span>
      {item.photoCount>1&&<span className="photoCount">{item.photoCount} фото</span>}
    </div>
    <div className="cardBody">
      <div className="cardPrice">{fmtPrice(item)}</div>
      <div className="cardTitle">{translateType(item.propertyType)} · {item.address||item.code}</div>
      {spec(item)&&<div className="cardSpecs">{spec(item)}</div>}
      {item.neighborhoods[0]&&<div className="cardLocation"><MapPin size={14}/>{prettyHood(item.neighborhoods[0])}</div>}
    </div>
  </button>;
}

function ListingDetail({item,busy,brandName,onBack,onAction,onGallery}:{item:Listing;busy:boolean;brandName:string;onBack:()=>void;onAction:(x:string)=>void;onGallery:()=>void}){
  const [photo,setPhoto]=useState(0);
  return <div className="detail">
    <div className="detailNav">
      <button className="roundBtn" onClick={onBack}><ArrowLeft size={21}/></button>
      <div className="detailCode">{item.code}</div>
      <button className="roundBtn" disabled={busy} onClick={()=>onAction('share')} aria-label="Поделиться объектом"><Share2 size={19}/></button>
    </div>
    <div className="gallery" onClick={onGallery}>
      <div className="galleryTrack" onScroll={e=>{
        const el=e.currentTarget; const i=Math.round(el.scrollLeft/el.clientWidth); if(i!==photo)setPhoto(i);
      }}>
        {(item.images.length?item.images:[null]).map((src,i)=><div className="slide" key={i}>
          {src?<img src={src} alt={`${item.address||item.code}, фото ${i+1}`}/>:<div className="noPhoto big"><Building2/></div>}
        </div>)}
      </div>
      {item.images.length>1&&<span className="galleryCount">{photo+1} / {item.images.length}</span>}
    </div>
    <div className="detailBody">
      <div className="detailMeta">{item.operation==='Venta'?'ПРОДАЖА':'АРЕНДА'} · {translateType(item.propertyType)}</div>
      <h1>{item.address||item.code}</h1>
      <div className="detailPrice">{fmtPrice(item)}</div>
      {spec(item)&&<div className="specGrid">
        {Object.entries({
          'Площадь':item.details.totalAreaM2?`${item.details.totalAreaM2} м²`:null,
          'Комнаты':item.details.rooms||null,
          'Спальни':item.details.bedrooms||null,
          'Ванные':item.details.bathrooms||null,
        }).filter(([,v])=>v).map(([k,v])=><div key={k}><span>{k}</span><strong>{v}</strong></div>)}
      </div>}
      {item.description&&<section className="detailSection"><h2>Об объекте</h2><p>{item.description}</p></section>}
      {!!item.highlightedFeatures.length&&<section className="detailSection"><h2>Особенности</h2><div className="featureList">
        {item.highlightedFeatures.map(x=><span key={x}>{x}</span>)}
      </div></section>}
      {!!item.notes.length&&<section className="noteBox">{item.notes.map(x=><p key={x}>{x}</p>)}</section>}
      <div className="detailQuickActions">
        <button onClick={()=>onAction('question')} disabled={busy}><MessageCircle size={17}/> Задать вопрос</button>
        <button onClick={()=>onAction('similar')} disabled={busy}><Search size={17}/> Подобрать похожие</button>
      </div>
      <button className="sourceLink" onClick={()=>tg?.openLink?tg.openLink(item.sourceUrl):window.open(item.sourceUrl,'_blank')}>
        Оригинал на {brandName} <ChevronRight size={17}/>
      </button>
    </div>
    <div className="detailActions">
      <button className="secondaryAction" disabled={busy} onClick={()=>onAction('availability')}><Check size={18}/> Проверить актуальность</button>
      <button className="primaryAction" disabled={busy} onClick={()=>onAction('viewing')}>Записаться на просмотр</button>
    </div>
  </div>;
}

function FilterSheet({filters,propertyTypes,neighborhoods,count,onClose,onUpdate,onToggleHood,onToggleType}:any){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet tall">
      <div className="sheetHandle"/><div className="sheetHead"><div><span>Фильтры</span><strong>{count} объектов</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>
      <div className="sheetScroll">
        <section className="filterSection"><h3>Район / город</h3><div className="chipsWrap">
          {neighborhoods.map((x:string)=><button key={x} className={filters.neighborhoods.includes(x)?'chip active':'chip'} onClick={()=>onToggleHood(x)}>{prettyHood(x)}</button>)}
        </div></section>
        <section className="filterSection"><h3>Тип объекта</h3><div className="chipsWrap">
          {propertyTypes.map((x:string)=><button key={x} className={filters.propertyTypes.includes(x)?'chip active':'chip'} onClick={()=>onToggleType(x)}>{translateType(x)}</button>)}
        </div></section>
        <section className="filterSection"><h3>Комнаты</h3><div className="roomsRow">
          {[1,2,3,4,5].map(n=><button key={n} className={filters.rooms===n?'room active':'room'} onClick={()=>onUpdate({rooms:filters.rooms===n?null:n})}>{n}</button>)}
        </div></section>
        <section className="filterSection"><h3>Бюджет до</h3><div className="budgetRow">
          <select value={filters.budgetCurrency} onChange={e=>onUpdate({budgetCurrency:e.target.value})}><option>USD</option><option>ARS</option></select>
          <input inputMode="numeric" value={filters.maxBudget} onChange={e=>onUpdate({maxBudget:e.target.value.replace(/\D/g,'')})} placeholder="Например, 150000"/>
        </div></section>
      </div>
      <div className="sheetFooter"><button className="primary" onClick={onClose}>Показать {count} {plural(count,'объект','объекта','объектов')}</button></div>
    </div>
  </div>;
}

function SaveSheet({notify,setNotify,count,busy,authenticated,botUsername,onClose,onSave}:any){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet">
      <div className="sheetHandle"/><div className="sheetHead"><div><span>Сохранить поиск</span><strong>{count} сейчас</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>
      <p className="sheetText">Критерии сохранятся. Вы сможете вернуться к ним позже.</p>
      <label className="notifyToggle">
        <div><Bell size={20}/><span><strong>Сообщать о новых вариантах</strong><small>Только когда появится новый подходящий объект</small></span></div>
        <input type="checkbox" checked={notify} onChange={e=>setNotify(e.target.checked)}/><i/>
      </label>
      {!authenticated&&<div className="authNote">Сохранение и уведомления работают, когда каталог открыт из {botUsername?'@'+botUsername:'Telegram-бота агентства'}.</div>}
      <button className="primary full" disabled={busy||!authenticated} onClick={onSave}>{busy?'Сохраняем…':'Сохранить поиск'}</button>
    </div>
  </div>;
}

function SavedSheet({items,onClose,onDelete}:{items:SavedSearch[];onClose:()=>void;onDelete:(id:string)=>void}){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet tall">
      <div className="sheetHandle"/><div className="sheetHead"><div><span>Мои поиски</span><strong>{items.length}</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>
      <div className="savedList">
        {items.map(item=><div className="savedItem" key={item.id}><div><strong>{item.label}</strong><span>{item.notify?'Уведомления включены':'Без уведомлений'}</span></div><button onClick={()=>onDelete(item.id)}>Удалить</button></div>)}
        {!items.length&&<div className="emptyMini"><Bookmark size={28}/><strong>Пока нет сохранённых поисков</strong><span>Настройте фильтры и сохраните поиск.</span></div>}
      </div>
    </div>
  </div>;
}

function prettyHood(x:string){
  const known:Record<string,string>={
    nunez:'Núñez',canuelas:'Cañuelas',martinez:'Martínez',
    'san nicolas':'San Nicolás','san cristobal':'San Cristóbal',
    'general rodriguez':'General Rodríguez','general pueyrredon':'General Pueyrredón',
    'vicente lopez':'Vicente López','velez sarsfield':'Vélez Sarsfield'
  };
  return known[x]||x.split(' ').map(w=>w[0].toUpperCase()+w.slice(1)).join(' ');
}
function translateType(x:string){
  return ({
    Departamento:'Квартира',Casa:'Дом',PH:'PH',Cochera:'Парковка',
    'Local Comercial':'Коммерция',Local:'Коммерция',
    'Terreno o Lote':'Участок',Terreno:'Участок',
    Oficina:'Офис','Depósito':'Склад',Propiedad:'Недвижимость'
  } as any)[x]||x;
}
function plural(n:number,one:string,few:string,many:string){const x=Math.abs(n)%100,y=x%10;if(x>10&&x<20)return many;if(y>1&&y<5)return few;if(y===1)return one;return many}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
