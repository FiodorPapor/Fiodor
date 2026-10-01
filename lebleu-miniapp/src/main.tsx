import React, {useEffect, useMemo, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {
  ArrowLeft, Bell, Bookmark, Building2, Check, ChevronRight,
  List, Map as MapIcon, MapPin, MessageCircle, Search, Share2, SlidersHorizontal, X
} from 'lucide-react';
import './styles.css';

const CatalogMap=React.lazy(()=>import('./CatalogMap'));

type Listing = {
  code:string; operation:string; propertyType:string; address:string;
  priceAmount:string; priceCurrency:string; details:Record<string,number>;
  highlightedFeatures:string[]; description:string; notes:string[];
  images:string[]; photoCount:number; sourceUrl:string; neighborhoods:string[]; listingToken:string;
  latitude?:number|null; longitude?:number|null;
};
type Catalog = {count:number; operations:Record<string,number>; neighborhoods:string[]; items:Listing[]};
type PublicConfig = {brandName:string; brandTagline:string; botUsername:string};
type Filters = {
  operation:string; query:string; neighborhoods:string[]; propertyTypes:string[];
  rooms:number|null; bedrooms:number|null; bathrooms:number|null; parking:boolean;
  minBudget:string; maxBudget:string; budgetCurrency:string;
  minArea:string; maxArea:string; features:string[]; sort:string;
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
  const hasBudget=Boolean(f.minBudget||f.maxBudget);
  return {
    operation:f.operation||undefined,
    query:f.query.trim()||undefined,
    neighborhoods:f.neighborhoods,
    propertyTypes:f.propertyTypes,
    rooms:f.rooms||undefined,
    minBedrooms:f.bedrooms||undefined,
    minBathrooms:f.bathrooms||undefined,
    parking:f.parking||undefined,
    minBudget:f.minBudget?Number(f.minBudget):undefined,
    maxBudget:f.maxBudget?Number(f.maxBudget):undefined,
    budgetCurrency:hasBudget?f.budgetCurrency:undefined,
    minArea:f.minArea?Number(f.minArea):undefined,
    maxArea:f.maxArea?Number(f.maxArea):undefined,
    features:f.features,
  };
}
function criteriaToFilters(criteria:Record<string,unknown>):Filters{
  const neighborhoods=Array.isArray(criteria.neighborhoods)?criteria.neighborhoods.map(String):[];
  const propertyTypes=Array.isArray(criteria.propertyTypes)?criteria.propertyTypes.map(String):[];
  const features=Array.isArray(criteria.features)?criteria.features.map(String):[];
  return {
    operation:typeof criteria.operation==='string'?criteria.operation:'',
    query:typeof criteria.query==='string'?criteria.query:'',
    neighborhoods,
    propertyTypes,
    rooms:criteria.rooms?Number(criteria.rooms):null,
    bedrooms:criteria.minBedrooms?Number(criteria.minBedrooms):criteria.bedrooms?Number(criteria.bedrooms):null,
    bathrooms:criteria.minBathrooms?Number(criteria.minBathrooms):null,
    parking:Boolean(criteria.parking),
    minBudget:criteria.minBudget?String(criteria.minBudget):'',
    maxBudget:criteria.maxBudget?String(criteria.maxBudget):'',
    budgetCurrency:typeof criteria.budgetCurrency==='string'?criteria.budgetCurrency:'USD',
    minArea:criteria.minArea?String(criteria.minArea):'',
    maxArea:criteria.maxArea?String(criteria.maxArea):'',
    features,
    sort:'recommended',
  };
}
function activeFilterCount(f:Filters){
  return (f.operation?1:0)+(f.query?1:0)+f.neighborhoods.length+f.propertyTypes.length+
    (f.rooms?1:0)+(f.bedrooms?1:0)+(f.bathrooms?1:0)+(f.parking?1:0)+
    (f.minBudget||f.maxBudget?1:0)+(f.minArea||f.maxArea?1:0)+f.features.length;
}
function canSaveSearch(f:Filters){
  return Boolean(
    f.query.trim()||f.neighborhoods.length||f.propertyTypes.length||f.rooms||f.bedrooms||
    f.bathrooms||f.parking||f.minBudget||f.maxBudget||f.minArea||f.maxArea||f.features.length
  );
}
function normalizedSearch(value:string){
  return value.toLowerCase().replace(/ё/g,'е').replace(/[^a-záéíóúñüа-я0-9]+/gi,' ').trim();
}
const FEATURE_OPTIONS=[
  {key:'balcon',label:'Балкон',terms:['balcón','balcon']},
  {key:'pileta',label:'Бассейн',terms:['pileta','piscina']},
  {key:'parrilla',label:'Гриль / parrilla',terms:['parrilla']},
  {key:'cochera',label:'Парковка',terms:['cochera','garage','garaje']},
  {key:'terraza',label:'Терраса',terms:['terraza']},
  {key:'jardin',label:'Сад',terms:['jardín','jardin']},
  {key:'gimnasio',label:'Спортзал',terms:['gimnasio','gym']},
  {key:'laundry',label:'Прачечная',terms:['laundry','lavadero']},
  {key:'aire',label:'Кондиционер',terms:['aire acondicionado']},
  {key:'amoblado',label:'Меблирована',terms:['amoblado','amueblado']},
  {key:'apto_credito',label:'Подходит под ипотеку',terms:['apto crédito','apto credito']},
  {key:'apto_profesional',label:'Для проф. использования',terms:['apto profesional']},
  {key:'baulera',label:'Кладовая',terms:['baulera']},
  {key:'sum',label:'SUM',terms:['sum']},
  {key:'ascensor',label:'Лифт',terms:['ascensor']},
  {key:'patio',label:'Патио',terms:['patio']},
  {key:'seguridad',label:'Охрана 24/7',terms:['seguridad 24','seguridad las 24']},
  {key:'a_estrenar',label:'Новый / без проживания',terms:['a estrenar']},
];
function itemHasFeature(item:Listing,key:string){
  const option=FEATURE_OPTIONS.find(x=>x.key===key);
  if(!option)return false;
  const hay=normalizedSearch([...(item.highlightedFeatures||[]),item.description||''].join(' '));
  return option.terms.some(term=>hay.includes(normalizedSearch(term)));
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
  operation:'',query:'',neighborhoods:[],propertyTypes:[],
  rooms:null,bedrooms:null,bathrooms:null,parking:false,
  minBudget:'',maxBudget:'',budgetCurrency:'USD',
  minArea:'',maxArea:'',features:[],sort:'recommended'
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
  const [viewMode,setViewMode]=useState<'list'|'map'>('list');
  const [questionOpen,setQuestionOpen]=useState(false);
  const [questionText,setQuestionText]=useState('');
  const [actionSuccess,setActionSuccess]=useState('');
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
      else if(questionOpen) setQuestionOpen(false);
      else if(actionSuccess) setActionSuccess('');
      else if(viewMode==='map') setViewMode('list');
    };
    if(selected||filtersOpen||saveOpen||savedOpen||questionOpen||actionSuccess||viewMode==='map'){
      tg.BackButton.show();
      tg.BackButton.onClick(goBack);
    } else tg.BackButton.hide();
    return ()=>{try{tg.BackButton.offClick(goBack);}catch{}};
  },[selected,filtersOpen,saveOpen,savedOpen,questionOpen,actionSuccess,viewMode]);

  useEffect(()=>{
    if(!tg)return;
    try{
      if(viewMode==='map')tg.disableVerticalSwipes?.();
      else tg.enableVerticalSwipes?.();
    }catch{}
    return ()=>{try{tg.enableVerticalSwipes?.();}catch{}};
  },[viewMode]);

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
    const queryTokens=q.split(/\s+/).filter(x=>x.length>=2&&!['ищу','нужна','нужен','хочу','вариант'].includes(x));
    const rows=catalog.items.filter(item=>{
      const d=item.details||{};
      if(filters.operation&&item.operation!==filters.operation) return false;
      if(filters.neighborhoods.length&&!filters.neighborhoods.some(x=>item.neighborhoods.includes(x))) return false;
      if(filters.propertyTypes.length&&!filters.propertyTypes.includes(item.propertyType)) return false;
      if(filters.rooms&&Number(d.rooms||0)!==filters.rooms) return false;
      if(filters.bedrooms&&Number(d.bedrooms||0)<filters.bedrooms) return false;
      if(filters.bathrooms&&Number(d.bathrooms||0)<filters.bathrooms) return false;
      if(filters.parking&&Number(d.parkingSpaces||0)<1) return false;
      if(filters.minArea&&Number(d.totalAreaM2||d.coveredAreaM2||0)<Number(filters.minArea)) return false;
      if(filters.maxArea&&Number(d.totalAreaM2||d.coveredAreaM2||0)>Number(filters.maxArea)) return false;
      if(filters.minBudget||filters.maxBudget){
        if(item.priceCurrency!==filters.budgetCurrency) return false;
        const price=Number(item.priceAmount||0);
        if(!price) return false;
        if(filters.minBudget&&price<Number(filters.minBudget)) return false;
        if(filters.maxBudget&&price>Number(filters.maxBudget)) return false;
      }
      if(filters.features.length&&!filters.features.every(key=>itemHasFeature(item,key))) return false;
      if(queryTokens.length){
        const operationWords=item.operation==='Venta'?'продажа купить покупка':'аренда снять арендовать';
        const hay=normalizedSearch([
          item.address,item.code,item.propertyType,translateType(item.propertyType),operationWords,item.description,
          ...item.highlightedFeatures,...item.highlightedFeatures.map(translateFeature),...item.neighborhoods
        ].join(' '));
        if(!queryTokens.every(token=>hay.includes(token))) return false;
      }
      return true;
    });
    return rows.sort((a,b)=>{
      if(filters.sort==='price_asc') return Number(a.priceAmount||0)-Number(b.priceAmount||0);
      if(filters.sort==='price_desc') return Number(b.priceAmount||0)-Number(a.priceAmount||0);
      if(filters.sort==='area_desc') return Number(b.details?.totalAreaM2||b.details?.coveredAreaM2||0)-Number(a.details?.totalAreaM2||a.details?.coveredAreaM2||0);
      return 0;
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
  async function submitListingIntent(action:'availability'|'viewing'|'question',message=''){
    if(!selected) return;
    if(!initData){showToast('Откройте каталог внутри Telegram');return;}
    setBusy(true);
    try{
      const res=await api<{message?:string}>('/api/v1/actions',{
        method:'POST',body:JSON.stringify({
          init_data:initData,listing_code:listingKey(selected),action,message:message||undefined,
          link_token:trackingToken||undefined
        })
      });
      haptic('success');
      setQuestionOpen(false);
      setQuestionText('');
      setActionSuccess(res.message||'Запрос отправлен');
    }catch(err:any){showToast(err.message||'Не удалось отправить запрос');}
    finally{setBusy(false);}
  }
  async function listingAction(action:string){
    if(!selected)return;
    if(action==='question'){
      setQuestionText('');
      setQuestionOpen(true);
      return;
    }
    if(action==='similar'){
      const d=selected.details||{};
      const price=Number(selected.priceAmount||0);
      const next:Filters={
        ...DEFAULT_FILTERS,
        operation:selected.operation,
        neighborhoods:selected.neighborhoods?.[0]?[selected.neighborhoods[0]]:[],
        propertyTypes:selected.propertyType?[selected.propertyType]:[],
        rooms:d.rooms||null,
        minBudget:price?String(Math.round(price*.7)):'',
        maxBudget:price?String(Math.round(price*1.3)):'',
        budgetCurrency:selected.priceCurrency||'USD',
      };
      setFilters(next);
      setSelected(null);
      setViewMode('list');
      searchStarted.current=true;
      event('search_started',selected,{via:'similar'});
      showToast('Показали похожие варианты');
      return;
    }
    if(action==='share'){
      if(!initData){showToast('Поделиться можно внутри Telegram');return;}
      setBusy(true);
      try{
        const res=await api<{telegram_url:string;share_url?:string;prepared_message_id?:string}>('/api/v1/actions',{
          method:'POST',body:JSON.stringify({
            init_data:initData,listing_code:listingKey(selected),action,link_token:trackingToken||undefined
          })
        });
        if(res.prepared_message_id&&typeof tg?.shareMessage==='function'){
          const listingAtShare=selected;
          tg.shareMessage(res.prepared_message_id,(sent:boolean)=>{
            if(sent){haptic('success');event('share_sent',listingAtShare,{via:'prepared_message'});}
          });
        }else{
          const destination=res.share_url||res.telegram_url;
          if(tg?.openTelegramLink)tg.openTelegramLink(destination);
          else window.location.href=destination;
        }
      }catch(err:any){showToast(err.message||'Не удалось поделиться');}
      finally{setBusy(false);}
      return;
    }
    if(action==='availability'||action==='viewing'){
      await submitListingIntent(action);
    }
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
    return <>
      <ListingDetail item={selected} busy={busy} brandName={config.brandName} onBack={()=>setSelected(null)}
        onAction={listingAction} onGallery={()=>event('gallery_opened',selected)} />
      {questionOpen&&<QuestionSheet value={questionText} onChange={setQuestionText} busy={busy}
        onClose={()=>setQuestionOpen(false)} onSubmit={()=>submitListingIntent('question',questionText)}/>}
      {actionSuccess&&<SuccessSheet message={actionSuccess} onClose={()=>setActionSuccess('')}/>}
      {toast&&<div className="toast"><Check size={17}/>{toast}</div>}
    </>;
  }

  return <div className="app">
    <header className="topbar">
      <div className="brand">
        <img className="brandLogo" src="/brand-logo.jpg" alt="" />
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
        <button className={activeFilterCount(filters)>0?'chip filterChip active':'chip filterChip'} onClick={()=>setFiltersOpen(true)}>
          <SlidersHorizontal size={15}/> Фильтры {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
        </button>
        {quickHoods.map(hood=><button key={hood} className={filters.neighborhoods.includes(hood)?'chip active':'chip'}
          onClick={()=>toggleNeighborhood(hood)}>{prettyHood(hood)}</button>)}
      </div>

      <div className="resultHeader">
        <div className="resultCount"><strong>{results.length}</strong><span> {plural(results.length,'объект','объекта','объектов')}</span></div>
        <div className="resultActions">
          <button className="filterPrimary" onClick={()=>setFiltersOpen(true)}>
            <SlidersHorizontal size={16}/> Фильтры
            {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
          </button>
          <select className="sortSelect" value={filters.sort} onChange={e=>update({sort:e.target.value})} aria-label="Сортировка">
            <option value="recommended">Сначала рекомендуемые</option>
            <option value="price_asc">Цена: ниже</option>
            <option value="price_desc">Цена: выше</option>
            <option value="area_desc">Площадь: больше</option>
          </select>
          <div className="viewToggle" aria-label="Вид каталога">
            <button className={viewMode==='list'?'active':''} onClick={()=>setViewMode('list')} aria-label="Список"><List size={16}/><span>Список</span></button>
            <button className={viewMode==='map'?'active':''} onClick={()=>setViewMode('map')} aria-label="Карта"><MapIcon size={16}/><span>Карта</span></button>
          </div>
        </div>
      </div>
      {activeFilterCount(filters)>0&&<div className="activeSummary">
        <span>{activeFilterCount(filters)} активных фильтра</span>
        <button onClick={()=>{setFilters(DEFAULT_FILTERS);searchStarted.current=false}}>Сбросить всё</button>
      </div>}

      <section className="cards">
        {results.map(item=><ListingCard key={listingKey(item)} item={item} onOpen={()=>openListing(item)}/>)}
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

    {viewMode==='map'&&<div className="mapFullscreen">
      <React.Suspense fallback={<div className="mapLoading full"><div className="spinner"/><span>Загружаем карту…</span></div>}>
        <CatalogMap items={results} onOpen={item=>openListing(item as Listing)} onFallback={()=>setViewMode('list')}/>
      </React.Suspense>
      <div className="mapTopOverlay">
        <button className="mapBackBtn" onClick={()=>setViewMode('list')}><ArrowLeft size={20}/><span>Список</span></button>
        <div className="mapResultPill"><strong>{results.length}</strong><span> {plural(results.length,'объект','объекта','объектов')}</span></div>
        <button className="mapFilterBtn" onClick={()=>setFiltersOpen(true)}>
          <SlidersHorizontal size={18}/><span>Фильтры</span>
          {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
        </button>
      </div>
    </div>}

    {viewMode==='list'&&canSaveSearch(filters)&&results.length>0&&
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
      {item.description&&<section className="detailSection"><h2>Описание на русском</h2><p>{item.description}</p></section>}
      {!!item.highlightedFeatures.length&&<section className="detailSection"><h2>Особенности</h2><div className="featureList">
        {item.highlightedFeatures.map(x=><span key={x}>{translateFeature(x)}</span>)}
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

function QuestionSheet({value,onChange,busy,onClose,onSubmit}:any){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet">
      <div className="sheetHandle"/>
      <div className="sheetHead"><div><span>Вопрос по объекту</span><strong>Ответим в Telegram</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>
      <p className="sheetText">Напишите, что хотите уточнить: документы, расходы, условия сделки, планировку или что-то ещё.</p>
      <textarea className="questionInput" autoFocus rows={5} maxLength={2000} value={value} onChange={e=>onChange(e.target.value)} placeholder="Например: можно ли купить этот объект с иностранным доходом?"/>
      <button className="primary full" disabled={busy||!value.trim()} onClick={onSubmit}>{busy?'Отправляем…':'Отправить вопрос'}</button>
    </div>
  </div>;
}

function SuccessSheet({message,onClose}:{message:string;onClose:()=>void}){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet successSheet">
      <div className="successIcon"><Check size={26}/></div>
      <h3>{message}</h3>
      <p>Запрос сохранён. Ответ придёт в этот же Telegram.</p>
      <button className="primary full" onClick={onClose}>Готово</button>
    </div>
  </div>;
}

function FilterSheet({filters,propertyTypes,neighborhoods,count,onClose,onUpdate,onToggleHood,onToggleType}:any){
  const [hoodQuery,setHoodQuery]=useState('');
  const toggleFeature=(key:string)=>onUpdate({features:filters.features.includes(key)
    ?filters.features.filter((x:string)=>x!==key):[...filters.features,key]});
  const visibleNeighborhoods=neighborhoods.filter((x:string)=>
    !hoodQuery.trim()||normalizedSearch(prettyHood(x)).includes(normalizedSearch(hoodQuery))
  );
  const residentialTypes=propertyTypes.filter((x:string)=>['Departamento','Casa','PH'].includes(x));
  const commercialTypes=propertyTypes.filter((x:string)=>['Local Comercial','Oficina'].includes(x));
  const landTypes=propertyTypes.filter((x:string)=>['Terreno o Lote','Campo','Cochera'].includes(x));
  return <div className="overlay filterOverlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet filterSheet">
      <div className="sheetHandle"/>
      <div className="sheetHead filterSheetHead">
        <div><span>Фильтры</span><strong>{count} объектов сейчас</strong></div>
        <div className="filterHeadActions">
          {activeFilterCount(filters)>0&&<button className="resetFiltersBtn" onClick={()=>onUpdate({...DEFAULT_FILTERS})}>Сбросить</button>}
          <button className="roundBtn" onClick={onClose}><X size={20}/></button>
        </div>
      </div>
      <div className="sheetScroll">
        <section className="filterSection filterStart">
          <h3>Что ищете?</h3>
          <div className="filterModeGrid">
            {[['','Все объекты'],['Venta','Купить'],['Alquiler','Арендовать']].map(([value,label])=>
              <button key={value} className={filters.operation===value?'active':''} onClick={()=>onUpdate({operation:value})}>{label}</button>
            )}
          </div>
        </section>
        <section className="filterSection">
          <h3>Район / город <small className="filterHint">можно выбрать несколько</small></h3>
          <div className="filterSearch">
            <Search size={16}/>
            <input value={hoodQuery} onChange={e=>setHoodQuery(e.target.value)} placeholder="Найти район"/>
            {hoodQuery&&<button onClick={()=>setHoodQuery('')} aria-label="Очистить"><X size={15}/></button>}
          </div>
          <div className="chipsWrap">
            {visibleNeighborhoods.map((x:string)=><button key={x} className={filters.neighborhoods.includes(x)?'chip active':'chip'} onClick={()=>onToggleHood(x)}>{prettyHood(x)}</button>)}
          </div>
        </section>
        <section className="filterSection"><h3>Тип объекта</h3>
          <div className="typePresetRow">
            {!!residentialTypes.length&&<button onClick={()=>onUpdate({propertyTypes:residentialTypes})}>Жилая</button>}
            {!!commercialTypes.length&&<button onClick={()=>onUpdate({propertyTypes:commercialTypes})}>Коммерческая</button>}
            {!!landTypes.length&&<button onClick={()=>onUpdate({propertyTypes:landTypes})}>Земля / паркинг</button>}
          </div>
          <div className="chipsWrap">
            {propertyTypes.map((x:string)=><button key={x} className={filters.propertyTypes.includes(x)?'chip active':'chip'} onClick={()=>onToggleType(x)}>{translateType(x)}</button>)}
          </div>
        </section>
        <section className="filterSection"><h3>Цена</h3>
          <div className="currencyTabs">
            {['USD','ARS'].map((cur:string)=><button key={cur} className={filters.budgetCurrency===cur?'active':''} onClick={()=>onUpdate({budgetCurrency:cur})}>{cur}</button>)}
          </div>
          <div className="rangeInputs">
            <input inputMode="numeric" value={filters.minBudget} onChange={e=>onUpdate({minBudget:e.target.value.replace(/\D/g,'')})} placeholder="От"/>
            <input inputMode="numeric" value={filters.maxBudget} onChange={e=>onUpdate({maxBudget:e.target.value.replace(/\D/g,'')})} placeholder="До"/>
          </div>
        </section>
        <section className="filterSection"><h3>Комнаты</h3><div className="roomsRow">
          {[1,2,3,4,5].map(n=><button key={n} className={filters.rooms===n?'room active':'room'} onClick={()=>onUpdate({rooms:filters.rooms===n?null:n})}>{n}</button>)}
        </div></section>
        <section className="filterSection splitFilter">
          <div><h3>Спален от</h3><div className="miniChoice">{[1,2,3,4].map(n=><button key={n} className={filters.bedrooms===n?'active':''} onClick={()=>onUpdate({bedrooms:filters.bedrooms===n?null:n})}>{n}+</button>)}</div></div>
          <div><h3>Ванных от</h3><div className="miniChoice">{[1,2,3].map(n=><button key={n} className={filters.bathrooms===n?'active':''} onClick={()=>onUpdate({bathrooms:filters.bathrooms===n?null:n})}>{n}+</button>)}</div></div>
        </section>
        <section className="filterSection"><h3>Площадь, м²</h3><div className="rangeInputs">
          <input inputMode="numeric" value={filters.minArea} onChange={e=>onUpdate({minArea:e.target.value.replace(/\D/g,'')})} placeholder="От"/>
          <input inputMode="numeric" value={filters.maxArea} onChange={e=>onUpdate({maxArea:e.target.value.replace(/\D/g,'')})} placeholder="До"/>
        </div></section>
        <section className="filterSection"><h3>Удобства</h3><div className="chipsWrap">
          <button className={filters.parking?'chip active':'chip'} onClick={()=>onUpdate({parking:!filters.parking})}>Парковка</button>
          {FEATURE_OPTIONS.filter(x=>x.key!=='cochera').map(x=><button key={x.key} className={filters.features.includes(x.key)?'chip active':'chip'} onClick={()=>toggleFeature(x.key)}>{x.label}</button>)}
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
    'Terreno o Lote':'Участок',Terreno:'Участок',Campo:'Земля / поле',
    Oficina:'Офис','Depósito':'Склад',Propiedad:'Недвижимость'
  } as any)[x]||x;
}
function translateFeature(x:string){
  const key=normalizedSearch(x);
  const known:Record<string,string>={
    'balcon':'Балкон','aire acondicionado':'Кондиционер','calefaccion':'Отопление',
    'parrilla':'Зона барбекю','piscina':'Бассейн','pileta':'Бассейн','sum':'Общий зал',
    'laundry':'Прачечная','lavadero':'Прачечная','solarium':'Солярий','gimnasio':'Спортзал',
    'gym':'Спортзал','jardin':'Сад','patio':'Патио','terraza':'Терраса','baulera':'Кладовая',
    'quincho':'Крытая зона барбекю','apto credito':'Подходит под ипотеку',
    'apto profesional':'Для профессионального использования','amoblado':'Меблирована',
    'ascensor':'Лифт','a estrenar':'Новостройка','luminoso':'Светлая','seguridad 24':'Охрана 24/7'
  };
  return known[key]||x;
}
function plural(n:number,one:string,few:string,many:string){const x=Math.abs(n)%100,y=x%10;if(x>10&&x<20)return many;if(y>1&&y<5)return few;if(y===1)return one;return many}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
