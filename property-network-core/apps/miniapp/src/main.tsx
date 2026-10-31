import React, {useEffect, useMemo, useRef, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {createPortal} from 'react-dom';
import {createRoot} from 'react-dom/client';
import {
  ArrowLeft, Bell, Bookmark, Building2, Check, ChevronLeft, ChevronRight,
  Languages, List, Map as MapIcon, MapPin, MessageCircle, Search, Share2, SlidersHorizontal, UserRound, Trash2, Download, Send, X
} from 'lucide-react';
import {APP_LANGUAGES, applyTenantDefaultLanguage, currentLanguage, localeForLanguage, setAppLanguage, tx, type AppLanguage} from './i18n';
import './styles.css';
import AgentInbox from './AgentInbox';

const CatalogMap=React.lazy(()=>import('./CatalogMap'));
const DetailMap=React.lazy(()=>import('./DetailMap'));

type Listing = {
  code:string; operation:string; status?:string; propertyType:string; address:string;
  priceAmount:string|number; priceCurrency:string; details:Record<string,number>;
  highlightedFeatures:string[]; description:string; notes:string[];
  descriptionKind?:string; sourceDescriptionAvailable?:boolean; summary?:string; summaryKind?:string;
  localized?:Partial<Record<AppLanguage,{summary?:string;description?:string}>>;
  additionalInfo?:Record<string,string>; services?:string[]; environments?:string[]; comforts?:string[];
  images:string[]; photoCount:number; sourceUrl:string; neighborhoods:string[]; listingToken:string; inventoryOwnerTenant?:string; routingMode?:string;
  latitude?:number|null; longitude?:number|null;
  geo?:{province?:string;department?:string;localGovernment?:string};
};
type Catalog = {count:number; operations:Record<string,number>; neighborhoods:string[]; items:Listing[]};
type PublicConfig = {
  tenantSlug:string; brandName:string; brandTagline:string; brandLogoUrl:string; botUsername:string;
  defaultLanguage:string; telegramChannelUrl:string; attributionCampaign:string; sourceLabel:string; marketplaceEnabled?:boolean; marketplaceVersion?:string; webAuthEnabled?:boolean; vapidPublicKey?:string; webPushEnabled?:boolean;
};
type Filters = {
  operation:string; query:string; neighborhoods:string[]; propertyTypes:string[];
  rooms:number|null; bedrooms:number|null; bathrooms:number|null; parking:boolean;
  minBudget:string; maxBudget:string; budgetCurrency:string;
  minArea:string; maxArea:string; features:string[]; sort:string;
};
type SavedSearch = {id:string; label:string; criteria:Record<string,unknown>; notify:boolean; active:boolean; createdAt:string};

const tg = window.Telegram?.WebApp;
const initData = tg?.initData || '';
const launchParams = new URLSearchParams(window.location.search);
const launchHashParams = new URLSearchParams(window.location.hash.replace(/^#/,''));
// Telegram Main Mini App deep links pass startapp both as initData.start_param
// and as the GET parameter tgWebAppStartParam. Some clients expose one earlier
// than the other, so accept both (plus hash as a defensive WebView fallback).
const telegramStartParam = String(
  tg?.initDataUnsafe?.start_param ||
  launchParams.get('tgWebAppStartParam') ||
  launchHashParams.get('tgWebAppStartParam') ||
  ''
);
const sectionTrackingMarker='__trk_';
const sectionParam=telegramStartParam.startsWith('section_') ? telegramStartParam.split(sectionTrackingMarker,1)[0] : '';
const sectionKey=sectionParam.startsWith('section_') ? sectionParam.slice('section_'.length) : '';
const embeddedTracking=telegramStartParam.includes(sectionTrackingMarker) ? telegramStartParam.split(sectionTrackingMarker,2)[1] : '';
const urlTracking = launchParams.get('trk') || '';
const trackingToken = urlTracking || embeddedTracking || (telegramStartParam.startsWith('trk_') ? telegramStartParam.slice(4) : '');
const directStartListing = telegramStartParam.startsWith('listing_') ? telegramStartParam.slice('listing_'.length) : '';
const requestedListing = launchParams.get('listing') || directStartListing;
const requestedSavedSearch = launchParams.get('saved') || '';
const requestedViewing = launchParams.get('viewing') || '';
type LaunchContext = {listing?:string|null;intent?:string|null;filters?:Record<string,unknown>;listingCodes?:string[]};
const SECTION_FILTERS:Record<string,Partial<Filters>>={
  rent_apartments:{operation:'Alquiler',propertyTypes:['Departamento','PH']},
  sale_apartments:{operation:'Venta',propertyTypes:['Departamento','PH']},
  rent_houses:{operation:'Alquiler',propertyTypes:['Casa']},
  sale_houses:{operation:'Venta',propertyTypes:['Casa']},
  parking:{propertyTypes:['Cochera']},
  land:{propertyTypes:['Terreno','Terreno o Lote','Finca','Campo']},
  commercial:{propertyTypes:['Oficina','Local Comercial','Edificio Comercial','Galpón','Depósito']},
  temporary:{operation:'Alquiler'},
  all:{},
};

function urlBase64ToUint8Array(value:string){const padding='='.repeat((4-value.length%4)%4);const raw=atob((value+padding).replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from([...raw].map(c=>c.charCodeAt(0)))}
async function enableWebPush(publicKey:string){if(!publicKey||!('serviceWorker'in navigator)||!('PushManager'in window)||!('Notification'in window))return false;let permission=Notification.permission;if(permission==='default')permission=await Notification.requestPermission();if(permission!=='granted')return false;const reg=await navigator.serviceWorker.ready;let sub=await reg.pushManager.getSubscription();if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlBase64ToUint8Array(publicKey)});await api('/api/v1/push-subscriptions',{method:'POST',body:JSON.stringify({init_data:initData,session_token:localStorage.getItem('person_session')||'',subscription:sub.toJSON()})});return true}

function api<T>(path:string, options?:RequestInit):Promise<T>{
  const controller=new AbortController();
  const timer=window.setTimeout(()=>controller.abort(),10000);
  return fetch(path,{
    ...options,
    signal:controller.signal,
    headers:{'content-type':'application/json',...(localStorage.getItem('person_session')?{'x-session-token':localStorage.getItem('person_session')!}:{}),...(options?.headers||{})}
  }).then(async r=>{
    if(!r.ok){
      let message=tx('common.error');
      try{ const j=await r.json(); message=typeof j.detail==='string'?j.detail:(j.detail?.message||message); }catch{}
      throw new Error(message);
    }
    return r.json();
  }).catch(err=>{
    if(err?.name==='AbortError') throw new Error(tx('errors.timeout'));
    throw err;
  }).finally(()=>window.clearTimeout(timer));
}

function fmtPrice(item:Listing){
  const n=Number(item.priceAmount);
  const value=Number.isFinite(n)?new Intl.NumberFormat(localeForLanguage(),{maximumFractionDigits:0}).format(n):item.priceAmount;
  return `${item.priceCurrency==='USD'?'US$':item.priceCurrency||''} ${value}`.trim();
}
function spec(item:Listing){
  const d=item.details||{};
  const rows:string[]=[];
  const area=d.totalAreaM2||d.coveredAreaM2;
  if(area) rows.push(tx('specs.sqm',{value:area}));
  if(d.rooms) rows.push(tx('specs.roomsShort',{count:d.rooms}));
  if(d.bedrooms) rows.push(tx('specs.bedroomsShort',{count:d.bedrooms}));
  return rows.join(' · ');
}
function localizedContent(item:Listing){
  const lang=currentLanguage();
  const own=item.localized?.[lang]||{};
  const structured=tx('listing.structured',{
    type:translateType(item.propertyType),
    operation:item.operation==='Venta'?tx('listing.sale'):tx('listing.rent'),
    address:item.address||item.code,
    specs:spec(item),
  }).replace(/\. \.$/,'.').replace(/\.\s*$/,'.');
  if(lang==='ru')return {summary:String(own.summary||item.summary||structured),description:String(own.description||item.description||''),fallback:false,automatic:false};
  if(lang==='es')return {summary:structured,description:String(own.description||''),fallback:false,automatic:false};
  if(own.description||own.summary)return {summary:structured,description:String(own.description||''),fallback:false,automatic:Boolean(own.description)};
  const source=item.localized?.es||{};
  return {summary:structured,description:String(source.description||''),fallback:Boolean(source.description),automatic:false};
}
function displayTagline(config:PublicConfig){
  return currentLanguage()==='ru'&&config.brandTagline?config.brandTagline:tx('brand.tagline');
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
  return Boolean(f.operation&&(
    f.query.trim()||f.neighborhoods.length||f.propertyTypes.length||f.rooms||f.bedrooms||
    f.bathrooms||f.parking||f.minBudget||f.maxBudget||f.minArea||f.maxArea||f.features.length
  ));
}
function normalizedSearch(value:string){
  return value.toLowerCase().replace(/ё/g,'е')
    .replace(/[áàâä]/g,'a').replace(/[éèêë]/g,'e').replace(/[íìîï]/g,'i')
    .replace(/[óòôö]/g,'o').replace(/[úùûü]/g,'u').replace(/ñ/g,'n')
    .replace(/[^a-zа-я0-9]+/gi,' ').trim();
}
const FEATURE_OPTIONS=[
  {key:'balcon',labelKey:'feature.balcon',terms:['balcón','balcon']},
  {key:'pileta',labelKey:'feature.pool',terms:['pileta','piscina']},
  {key:'parrilla',labelKey:'feature.parrilla',terms:['parrilla']},
  {key:'cochera',labelKey:'feature.parking',terms:['cochera','garage','garaje']},
  {key:'terraza',labelKey:'feature.terrace',terms:['terraza']},
  {key:'jardin',labelKey:'feature.garden',terms:['jardín','jardin']},
  {key:'gimnasio',labelKey:'feature.gym',terms:['gimnasio','gym']},
  {key:'laundry',labelKey:'feature.laundry',terms:['laundry','lavadero']},
  {key:'aire',labelKey:'feature.ac',terms:['aire acondicionado']},
  {key:'amoblado',labelKey:'feature.furnished',terms:['amoblado','amueblado']},
  {key:'apto_credito',labelKey:'feature.mortgage',terms:['apto crédito','apto credito']},
  {key:'apto_profesional',labelKey:'feature.professional',terms:['apto profesional']},
  {key:'baulera',labelKey:'feature.storage',terms:['baulera']},
  {key:'sum',labelKey:'feature.sum',terms:['sum']},
  {key:'ascensor',labelKey:'feature.elevator',terms:['ascensor']},
  {key:'patio',labelKey:'feature.patio',terms:['patio']},
  {key:'seguridad',labelKey:'feature.security',terms:['seguridad 24','seguridad las 24']},
  {key:'a_estrenar',labelKey:'feature.new',terms:['a estrenar']},
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
const DEFAULT_CONFIG:PublicConfig={
  tenantSlug:'default',brandName:'',brandTagline:'',brandLogoUrl:'/brand-logo.jpg',botUsername:'',webAuthEnabled:false,
  defaultLanguage:'ru',telegramChannelUrl:'',attributionCampaign:'property_catalog',sourceLabel:'original_source',marketplaceEnabled:false
};
function brandInitials(name:string){
  const parts=name.trim().split(/\s+/).filter(Boolean);
  return (parts.length>1?parts.slice(0,2).map(x=>x[0]).join(''):name.slice(0,2)).toUpperCase()||'RE';
}

function App(){
  const {i18n}=useTranslation();
  const lang=(i18n.resolvedLanguage||currentLanguage()).split('-')[0] as AppLanguage;
  const [config,setConfig]=useState<PublicConfig>(DEFAULT_CONFIG);
  const [catalog,setCatalog]=useState<Catalog|null>(null);
  const [loadError,setLoadError]=useState('');
  const [filters,setFilters]=useState<Filters>(DEFAULT_FILTERS);
  const [selected,setSelected]=useState<Listing|null>(null);
  const [filtersOpen,setFiltersOpen]=useState(false);
  const [saveOpen,setSaveOpen]=useState(false);
  const [savedOpen,setSavedOpen]=useState(false);
  const [journeyOpen,setJourneyOpen]=useState<'messages'|'profile'|null>(null);
  const [activeConversation,setActiveConversation]=useState<string>('');
  const [installPrompt,setInstallPrompt]=useState<any>(null);
  const [telegramInstall,setTelegramInstall]=useState(false);
  const [notify,setNotify]=useState(true);
  const [saveScope,setSaveScope]=useState<'current'|'all'>('current');
  const [welcomeAlerts,setWelcomeAlerts]=useState(()=>{const raw=localStorage.getItem('property_alerts_intro_seen'); if(!raw)return true; const n=Number(raw); return Number.isFinite(n)&&Date.now()-n>7*86400000;});
  const [saved,setSaved]=useState<SavedSearch[]>([]);
  const [toast,setToast]=useState('');
  const [busy,setBusy]=useState(false);
  const [viewMode,setViewMode]=useState<'list'|'map'>('list');
  const mapViewportRef=useRef<{center:[number,number];zoom:number}|null>(null);
  const catalogScrollRef=useRef(0);
  const detailScrollKeyRef=useRef('');
  const [questionOpen,setQuestionOpen]=useState(false);
  const [questionText,setQuestionText]=useState('');
  const [viewingRequestOpen,setViewingRequestOpen]=useState(false);
  const [viewingReadiness,setViewingReadiness]=useState<any>(null);
  const [viewingFacts,setViewingFacts]=useState<Record<string,any>>({});
  const [actionSuccess,setActionSuccess]=useState<{message:string;detail:string}|null>(null);
  const [webContactOpen,setWebContactOpen]=useState(false);
  const [webContact,setWebContact]=useState<{name:string;email:string;phone:string}>(()=>{try{return JSON.parse(localStorage.getItem('property_web_contact')||'null')||{name:'',email:'',phone:''}}catch{return {name:'',email:'',phone:''}}});
  const [pendingWebAction,setPendingWebAction]=useState<{action:'viewing'|'question';message:string;viewingWindows:string[]}|null>(null);
  const [viewingPrompt,setViewingPrompt]=useState(requestedViewing);
  const [galleryOpen,setGalleryOpen]=useState(false);
  const [galleryStart,setGalleryStart]=useState(0);
  const [outboundClickToken,setOutboundClickToken]=useState('');
  const [launchCodes,setLaunchCodes]=useState<string[]|null>(null);
  const searchStarted=useRef(false);

  useEffect(()=>{
    if(tg){
      try{
        tg.ready(); tg.expand();
        tg.setHeaderColor?.('bg_color');
        tg.setBackgroundColor?.('bg_color');
        tg.setBottomBarColor?.('bg_color');
        tg.disableVerticalSwipes?.();
      }catch{}
    }
    if(initData){
      api<{outbound_click_token?:string}>('/api/v1/session',{method:'POST',body:JSON.stringify({init_data:initData})})
        .then(data=>setOutboundClickToken(data.outbound_click_token||''))
        .catch(()=>{});
    }
    else if(!localStorage.getItem('person_session')){
      api<{sessionToken:string}>('/api/v1/auth/device',{method:'POST',body:'{}'})
        .then(data=>{localStorage.setItem('person_session',data.sessionToken);window.dispatchEvent(new Event('pn:auth-ready'))})
        .catch(()=>{});
    }
    api<Partial<PublicConfig>>('/api/v1/config').then(data=>{
      const next={...DEFAULT_CONFIG,...data};
      setConfig(next);
      void applyTenantDefaultLanguage(next.defaultLanguage);
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
            .catch(()=>showToast(tx('errors.listingGone')));
        }
      }else if(requestedSavedSearch&&initData){
        restoreSavedSearch(requestedSavedSearch);
      }else if(sectionKey&&SECTION_FILTERS[sectionKey]){
        const directFilters=SECTION_FILTERS[sectionKey];
        setLaunchCodes(null);
        setFilters(prev=>({...prev,...directFilters}));
        // Section routing is authoritative and local. Tracking enrichment is optional:
        // if Growth Core resolves, use its exact topic membership without controlling navigation.
        if(trackingToken){
          api<LaunchContext>(`/api/v1/launch-context?token=${encodeURIComponent(trackingToken)}`).then(context=>{
            if(Array.isArray(context.listingCodes)&&context.listingCodes.length)setLaunchCodes(context.listingCodes.map(String));
          }).catch(()=>{});
        }
      }else if(trackingToken){
        api<LaunchContext>(`/api/v1/launch-context?token=${encodeURIComponent(trackingToken)}`).then(context=>{
          if(context.listing){
            const item=data.items.find(x=>listingKey(x)===context.listing||x.code===context.listing);
            if(item) openListing(item);
            else api<Listing>(`/api/v1/catalog/${encodeURIComponent(context.listing)}`)
              .then(full=>{setSelected(full);event('listing_opened',full);})
              .catch(()=>showToast(tx('errors.listingGone')));
            return;
          }
          const launchFilters=context.filters||{};
          setFilters(prev=>({
            ...prev,
            operation:typeof launchFilters.operation==='string'?launchFilters.operation:prev.operation,
            query:typeof launchFilters.query==='string'?launchFilters.query:prev.query,
            neighborhoods:Array.isArray(launchFilters.neighborhoods)?launchFilters.neighborhoods.map(String):prev.neighborhoods,
            propertyTypes:Array.isArray(launchFilters.propertyTypes)?launchFilters.propertyTypes.map(String):prev.propertyTypes,
          }));
          if(Array.isArray(context.listingCodes)&&context.listingCodes.length)setLaunchCodes(context.listingCodes.map(String));
        }).catch(()=>{});
      }
    }).catch(err=>{
      const message=err?.message||tx('errors.catalog');
      setLoadError(message);
      showToast(message);
    });
  },[]);

  useEffect(()=>{
    const messages=()=>{setJourneyOpen('messages');setSavedOpen(false)};
    const savedEvt=()=>{void loadSaved();setSavedOpen(true);setJourneyOpen(null)};
    window.addEventListener('pn:messages',messages);window.addEventListener('pn:saved',savedEvt);
    return()=>{window.removeEventListener('pn:messages',messages);window.removeEventListener('pn:saved',savedEvt)};
  },[]);

  useEffect(()=>{
    if(!welcomeAlerts)return;
    const t=window.setTimeout(()=>{},0);return()=>window.clearTimeout(t);
  },[welcomeAlerts]);

  useEffect(()=>{
    if(!config.brandName)return;
    const tagline=displayTagline(config);
    document.title=tagline?`${config.brandName} · ${tagline}`:config.brandName;
    document.querySelector('meta[name="description"]')?.setAttribute('content',tx('brand.meta',{brand:config.brandName}));
  },[config,i18n.language]);

  useEffect(()=>{
    if(initData) return;
    const onPopState=()=>{
      if(galleryOpen)setGalleryOpen(false);
      else if(questionOpen)setQuestionOpen(false);
      else if(viewingRequestOpen)setViewingRequestOpen(false);
      else if(actionSuccess)setActionSuccess(null);
      else if(webContactOpen){setWebContactOpen(false);setPendingWebAction(null)}
      else if(journeyOpen)setJourneyOpen(null);
      else if(savedOpen)setSavedOpen(false);
      else if(saveOpen)setSaveOpen(false);
      else if(filtersOpen)setFiltersOpen(false);
      else if(selected){setSelected(null);requestAnimationFrame(()=>requestAnimationFrame(()=>window.scrollTo(0,catalogScrollRef.current)))}
      else if(viewMode==='map')setViewMode('list');
    };
    window.addEventListener('popstate',onPopState);
    return()=>window.removeEventListener('popstate',onPopState);
  },[galleryOpen,questionOpen,viewingRequestOpen,actionSuccess,webContactOpen,journeyOpen,savedOpen,saveOpen,filtersOpen,selected,viewMode]);

  useEffect(()=>{
    if(initData)return;
    const modal=galleryOpen||questionOpen||viewingRequestOpen||Boolean(actionSuccess)||webContactOpen||Boolean(journeyOpen)||savedOpen||saveOpen||filtersOpen;
    const key=selected?listingKey(selected):'';
    const state=window.history.state||{};
    if(key&&state.pnListing!==key)window.history.pushState({...state,pnListing:key},'',window.location.href);
    else if(modal&&!state.pnModal)window.history.pushState({...state,pnModal:true},'',window.location.href);
    else if(viewMode==='map'&&!state.pnMap)window.history.pushState({...state,pnMap:true},'',window.location.href);
  },[galleryOpen,questionOpen,viewingRequestOpen,actionSuccess,webContactOpen,journeyOpen,savedOpen,saveOpen,filtersOpen,selected,viewMode]);

  useEffect(()=>{
    if(!tg?.BackButton) return;
    const goBack=()=>{
      if(galleryOpen) setGalleryOpen(false);
      else if(questionOpen) setQuestionOpen(false);
      else if(viewingRequestOpen) setViewingRequestOpen(false);
      else if(actionSuccess) setActionSuccess(null);
      else if(viewingPrompt) setViewingPrompt('');
      else if(journeyOpen) setJourneyOpen(null);
      else if(webContactOpen){setWebContactOpen(false);setPendingWebAction(null);}
      else if(selected) closeListing();
      else if(filtersOpen) setFiltersOpen(false);
      else if(saveOpen) setSaveOpen(false);
      else if(savedOpen) setSavedOpen(false);
      else if(viewMode==='map') setViewMode('list');
    };
    if(galleryOpen||selected||filtersOpen||saveOpen||savedOpen||questionOpen||viewingRequestOpen||actionSuccess||viewingPrompt||journeyOpen||webContactOpen||viewMode==='map'){
      tg.BackButton.show();
      tg.BackButton.onClick(goBack);
    } else tg.BackButton.hide();
    return ()=>{try{tg.BackButton.offClick(goBack);}catch{}};
  },[galleryOpen,selected,filtersOpen,saveOpen,savedOpen,questionOpen,viewingRequestOpen,actionSuccess,viewingPrompt,journeyOpen,webContactOpen,viewMode]);

  useEffect(()=>{
    if(!tg)return;
    try{
      if(viewMode==='map'||selected)tg.disableVerticalSwipes?.();
      else tg.enableVerticalSwipes?.();
    }catch{}
    return ()=>{try{tg.enableVerticalSwipes?.();}catch{}};
  },[viewMode,selected]);

  useEffect(()=>{
    if(viewMode!=='map'||selected) return;
    const oldBody=document.body.style.overflow;
    const oldHtml=document.documentElement.style.overflow;
    document.body.style.overflow='hidden';
    document.documentElement.style.overflow='hidden';
    return ()=>{
      document.body.style.overflow=oldBody;
      document.documentElement.style.overflow=oldHtml;
    };
  },[viewMode,selected]);

  useEffect(()=>{
    const key=selected?listingKey(selected):'';
    if(!key){
      detailScrollKeyRef.current='';
      return;
    }
    if(detailScrollKeyRef.current===key)return;
    detailScrollKeyRef.current=key;
    const reset=()=>{
      window.scrollTo({top:0,left:0,behavior:'auto'});
      try{document.scrollingElement?.scrollTo({top:0,left:0,behavior:'auto'});}catch{}
    };
    reset();
    requestAnimationFrame(()=>requestAnimationFrame(reset));
  },[selected?listingKey(selected):'']);

  useEffect(()=>{
    if(savedOpen&&initData) loadSaved();
  },[savedOpen]);
  useEffect(()=>{
    if(window.matchMedia?.('(display-mode: standalone)')?.matches)return;
    const before=(event:any)=>{event.preventDefault();setInstallPrompt(event)};
    const installed=()=>setInstallPrompt(null);
    window.addEventListener('beforeinstallprompt',before); window.addEventListener('appinstalled',installed);
    return()=>{window.removeEventListener('beforeinstallprompt',before);window.removeEventListener('appinstalled',installed)};
  },[]);
  async function installApp(){if(telegramInstall&&typeof tg?.addToHomeScreen==='function'){try{tg.addToHomeScreen();setTelegramInstall(false)}catch{};return}if(!installPrompt)return;try{await installPrompt.prompt();const choice=await installPrompt.userChoice;if(choice.outcome==='accepted')setInstallPrompt(null)}catch{}}
  useEffect(()=>{if(typeof tg?.addToHomeScreen==='function'){try{if(typeof tg.checkHomeScreenStatus==='function')tg.checkHomeScreenStatus((status:string)=>setTelegramInstall(!['added','unsupported'].includes(status)));else setTelegramInstall(true)}catch{}}},[]);

  async function changeLanguage(next:AppLanguage){
    await setAppLanguage(next);
    event('language_changed',undefined,{language:next});
  }
  function openTelegramFeed(){
    const url=config.telegramChannelUrl;
    if(!url)return;
    event('channel_opened',undefined,{tenant:config.tenantSlug});
    if(tg?.openTelegramLink) tg.openTelegramLink(url);
    else window.location.href=url;
  }
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
    const queryTokens=q.split(/\s+/).filter(x=>x.length>=2&&!['ищу','нужна','нужен','хочу','вариант','busco','quiero','necesito','looking','want','need'].includes(x));
    const rows=catalog.items.filter(item=>{
      const d=item.details||{};
      if(launchCodes?.length&&!launchCodes.includes(listingKey(item))&&!launchCodes.includes(item.code)) return false;
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
        const operationWords=item.operation==='Venta'?'продажа купить покупка venta vender comprar compra sale buy purchase':'аренда снять арендовать alquiler alquilar rent rental';
        const hay=normalizedSearch([
          item.address,item.code,item.propertyType,translateType(item.propertyType),operationWords,item.description,item.summary,
          ...Object.values(item.localized||{}).flatMap(x=>[x?.summary||'',x?.description||'']),
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
  },[catalog,filters,launchCodes]);

  const propertyTypes=useMemo(()=>catalog?Array.from(new Set(catalog.items.map(x=>x.propertyType).filter(Boolean))).sort():[],[catalog]);
  const quickHoods=['palermo','belgrano','nunez','recoleta','colegiales'].filter(x=>catalog?.neighborhoods.includes(x));

  function closeListing(){
    setSelected(null);
    if(viewMode==='list'){
      const top=catalogScrollRef.current;
      requestAnimationFrame(()=>requestAnimationFrame(()=>window.scrollTo({top,left:0,behavior:'auto'})));
    }
  }

  async function openListing(item:Listing){
    haptic();
    if(!selected&&viewMode==='list')catalogScrollRef.current=window.scrollY||document.documentElement.scrollTop||0;
    // Open immediately with the lightweight card data, then hydrate the full
    // gallery/description in the background. This keeps Telegram navigation instant.
    setSelected(item);
    event('listing_opened',item);
    try{
      const key=listingKey(item);
      const full=await api<Listing>(`/api/v1/catalog/${encodeURIComponent(key)}`);
      setSelected(current=>current&&listingKey(current)===key?full:current);
    }catch(err:any){
      showToast(err.message||tx('errors.details'));
    }
  }
  function openFullGallery(index:number){
    if(!selected?.images?.length)return;
    setGalleryStart(Math.max(0,Math.min(index,selected.images.length-1)));
    setGalleryOpen(true);
    event('gallery_opened',selected,{photo_index:index});
    haptic();
  }
  function openOriginal(item:Listing){
    const clickId=(globalThis.crypto?.randomUUID?.()||`c_${Date.now()}_${Math.random().toString(36).slice(2,9)}`);
    if(outboundClickToken){
      const params=new URLSearchParams({
        listing_code:listingKey(item),
        click_token:outboundClickToken,
        click_id:clickId,
      });
      if(trackingToken)params.set('trk',trackingToken);
      const destination=`${window.location.origin}/api/v1/out/original?${params.toString()}`;
      if(tg?.openLink)tg.openLink(destination);
      else window.open(destination,'_blank','noopener,noreferrer');
      return;
    }
    // Fallback only if the short-lived signed redirect token has not loaded yet.
    if(initData){
      const body=JSON.stringify({
        init_data:initData,event_name:'original_opened',listing_code:listingKey(item),
        properties:{click_id:clickId,destination:config.sourceLabel,via:'client_fallback'},link_token:trackingToken||undefined
      });
      try{
        fetch('/api/v1/events',{method:'POST',headers:{'content-type':'application/json'},body,keepalive:true}).catch(()=>{});
      }catch{}
    }
    let destination=item.sourceUrl;
    try{
      const url=new URL(item.sourceUrl);
      url.searchParams.set('utm_source','telegram');
      url.searchParams.set('utm_medium','miniapp');
      url.searchParams.set('utm_campaign',config.attributionCampaign);
      url.searchParams.set('utm_content',listingKey(item));
      url.searchParams.set('lb_click',clickId);
      destination=url.toString();
    }catch{}
    if(tg?.openLink)tg.openLink(destination);
    else window.open(destination,'_blank','noopener,noreferrer');
  }

  async function submitListingIntent(action:'viewing'|'question',message='',windows:string[]=[]){
    if(!selected) return;
    if(!initData&&!webContact.email.trim()&&!webContact.phone.trim()){
      setPendingWebAction({action,message,viewingWindows:windows});setWebContactOpen(true);return;
    }
    if(initData){
      const allowed=await ensureWriteAccess();
      if(!allowed){showToast(tx('errors.writeAccess'));return;}
    }
    setBusy(true);
    try{
      let res:{message?:string;delivery_message?:string};
      let sessionToken=localStorage.getItem('person_session')||'';
      if(!initData&&!sessionToken){
        const auth=await api<{sessionToken:string}>('/api/v1/auth/device',{method:'POST',body:'{}'});
        sessionToken=auth.sessionToken;localStorage.setItem('person_session',sessionToken);
      }
      if(!initData&&sessionToken&&(webContact.name.trim()||webContact.email.trim()||webContact.phone.trim())){
        await api('/api/v1/profile',{method:'POST',body:JSON.stringify({init_data:'',session_token:sessionToken,preferred_language:lang,facts:{name:webContact.name.trim(),email:webContact.email.trim(),phone:webContact.phone.trim()}})});
      }
      const partnerInventory=config.marketplaceEnabled&&selected.routingMode==='collaboration_required';
      const hasAccount=Boolean(initData||sessionToken);
      if(hasAccount&&config.marketplaceEnabled&&(action==='question'||action==='viewing'||partnerInventory)){
        const text=message||(action==='viewing'?'':tx('listing.ask'));
        await api<{id:string;routingMode?:string}>('/api/v1/conversations',{method:'POST',body:JSON.stringify({init_data:initData,listing_code:listingKey(selected),intent:action,message:text,viewing_windows:windows,source_language:lang,source_channel:initData?'telegram':'web'})});
        const responseCopy=lang==='es'?{viewing:{message:'Solicitud de visita enviada',detail:'El agente verificará la propiedad y propondrá un horario concreto. La respuesta quedará en «Mis consultas».'},question:{message:'Consulta enviada',detail:'La respuesta quedará guardada en «Mis consultas».'}}:lang==='en'?{viewing:{message:'Viewing request sent',detail:'The agent will verify the property and propose a specific time. The reply will be saved in “My inquiries”.'},question:{message:'Question sent',detail:'The reply will be saved in “My inquiries”.'}}:{viewing:{message:'Запрос на просмотр отправлен',detail:initData?'Агент проверит объект и предложит конкретное время. Ответ придёт в Telegram и сохранится в «Моих обращениях».':'Агент проверит объект и предложит конкретное время. Ответ сохранится в «Моих обращениях».'},question:{message:'Вопрос отправлен',detail:initData?'Ответ придёт в Telegram и сохранится в «Моих обращениях».':'Ответ сохранится в «Моих обращениях».'}};
        const chosen=action==='viewing'?responseCopy.viewing:responseCopy.question;res={message:chosen.message,delivery_message:chosen.detail};
      }else{
        res=await api<{message?:string;delivery_message?:string}>('/api/v1/actions',{
          method:'POST',body:JSON.stringify({
            init_data:initData,session_token:localStorage.getItem('person_session')||'',listing_code:listingKey(selected),action,message:message||undefined,
            link_token:trackingToken||undefined,web_contact:initData?undefined:{...webContact,language:lang}
          })
        });
      }
      haptic('success');
      setQuestionOpen(false);
      setViewingRequestOpen(false);
      setQuestionText('');
      setActionSuccess({message:res.message||tx('actions.sent'),detail:res.delivery_message||tx('actions.savedContact')});
    }catch(err:any){showToast(err.message||tx('errors.send'));}
    finally{setBusy(false);}
  }
  async function submitViewingReadiness(){
    if(!selected)return;
    const sessionToken=localStorage.getItem('person_session')||'';
    setBusy(true);
    try{
      await api('/api/v1/profile',{method:'POST',body:JSON.stringify({init_data:initData,session_token:sessionToken,preferred_language:lang,facts:viewingFacts})});
      const ready=await api<any>(`/api/v1/readiness?listing_code=${encodeURIComponent(listingKey(selected))}&init_data=${encodeURIComponent(initData)}`);
      setViewingReadiness(ready);setViewingFacts({...ready.snapshot});
      if(!ready.ready){showToast(currentLanguage()==='es'?'Faltan algunos datos':currentLanguage()==='en'?'A few details are still missing':'Осталось заполнить несколько пунктов');return;}
      await submitListingIntent('viewing','',[]);
    }catch(err:any){showToast(err.message||tx('errors.send'));}
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
      showToast(tx('actions.similarShown'));
      return;
    }
    if(action==='share'){
      if(!initData){
        const shareUrl=window.location.href; const shareText=`${selected.address} · ${selected.priceCurrency||''} ${selected.priceAmount||''}`.trim();
        try{if(typeof navigator.share==='function'){await navigator.share({title:selected.address,text:shareText,url:shareUrl});}else{await navigator.clipboard.writeText(shareUrl);showToast('Ссылка скопирована');}}catch{} return;
      }
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
      }catch(err:any){showToast(err.message||tx('errors.share'));}
      finally{setBusy(false);}
      return;
    }
    if(action==='viewing'){
      setBusy(true);
      try{
        let sessionToken=localStorage.getItem('person_session')||'';
        if(!initData&&!sessionToken){
          const auth=await api<{sessionToken:string}>('/api/v1/auth/device',{method:'POST',body:'{}'});
          sessionToken=auth.sessionToken;localStorage.setItem('person_session',sessionToken);
        }
        const ready=await api<any>(`/api/v1/readiness?listing_code=${encodeURIComponent(listingKey(selected))}&init_data=${encodeURIComponent(initData)}`);
        setViewingReadiness(ready);setViewingFacts({...ready.snapshot});setViewingRequestOpen(true);
      }catch(err:any){showToast(err.message||tx('errors.send'));}
      finally{setBusy(false);}
    }
  }
  async function saveSearch(){
    if(!initData&&!localStorage.getItem('person_session')){setSaveOpen(false);setJourneyOpen('profile');return;}
    if(saveScope!=='all'&&!canSaveSearch(filters)){showToast(tx('save.criteriaNeeded'));return;}
    setBusy(true);
    try{
      if(notify){
        if(initData){const allowed=await ensureWriteAccess();if(!allowed){showToast(tx('errors.writeAccess'));return;}}
        else if(config.vapidPublicKey){const allowed=await enableWebPush(config.vapidPublicKey);if(!allowed){showToast('Уведомления не разрешены. Поиск всё равно можно сохранить без них.');setNotify(false);}}
      }
      const res=await api<{label:string;matches_now:number}>('/api/v1/saved-searches',{
        method:'POST',
        body:JSON.stringify({
          init_data:initData,session_token:localStorage.getItem('person_session')||'',criteria:saveScope==='all'?{all:true}:filtersToCriteria(filters),notify:Boolean(notify),link_token:trackingToken||undefined
        })
      });
      setSaveOpen(false); setSaveScope('current');
      haptic('success');
      showToast(notify?tx('actions.searchSavedCount',{count:res.matches_now}):tx('actions.searchSaved'));
    }catch(err:any){showToast(err.message||tx('errors.save'));}
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
        showToast(tx('actions.savedSearch'));
      }
    }catch(err:any){
      showToast(err.message||tx('errors.savedOpen'));
    }
  }
  async function loadSaved(){
    try{
      const res=await api<{items:SavedSearch[]}>(`/api/v1/saved-searches?init_data=${encodeURIComponent(initData)}`);
      setSaved(res.items);
    }catch(err:any){showToast(err.message||tx('errors.load'));}
  }
  async function respondViewing(id:string,action:'confirm'|'cancel'){
    try{
      await api(`/api/v1/viewings/${id}/${action}?init_data=${encodeURIComponent(initData)}`,{method:'POST'});
      setViewingPrompt(''); haptic('success'); showToast(action==='confirm'?tx('viewing.confirmed'):tx('viewing.cancelled'));
    }catch(err:any){showToast(err.message||tx('errors.send'));}
  }
  async function setSavedState(id:string,patch:{notify?:boolean;active?:boolean}){
    try{
      const res=await api<{notify:boolean;active:boolean}>(`/api/v1/saved-searches/${id}`,{method:'PATCH',body:JSON.stringify({init_data:initData,session_token:localStorage.getItem('person_session')||'',...patch})});
      setSaved(x=>x.map(s=>s.id===id?{...s,notify:res.notify,active:res.active}:s)); haptic('success');
    }catch(err:any){showToast(err.message||tx('errors.save'));}
  }
  async function removeSaved(id:string){
    try{
      await api(`/api/v1/saved-searches/${id}?init_data=${encodeURIComponent(initData)}`,{method:'DELETE'});
      setSaved(x=>x.map(s=>s.id===id?{...s,active:false}:s)); haptic('success');
    }catch(err:any){showToast(err.message||tx('errors.remove'));}
  }

  if(!catalog&&loadError){
    return <div className="loading loadError">
      <div className="emptyIcon"><X size={26}/></div>
      <strong>{tx('errors.catalogOpen')}</strong>
      <span>{loadError}</span>
      <button className="primary" onClick={()=>window.location.reload()}>{tx('common.retry')}</button>
    </div>;
  }

  if(!catalog){
    return <div className="loading"><div className="spinner"/><span>{config.brandName?tx('catalog.loading',{brand:config.brandName}):tx('common.loading')}</span></div>;
  }

  if(selected){
    return <>
      <ListingDetail item={selected} busy={busy} brandName={config.brandName} onBack={closeListing}
        onAction={listingAction} onGallery={openFullGallery} onOpenOriginal={()=>openOriginal(selected)} onLanguage={changeLanguage} />
      {galleryOpen&&createPortal(<FullGallery item={selected} initialIndex={galleryStart} onClose={()=>setGalleryOpen(false)}/>,document.body)}
      {questionOpen&&<QuestionSheet value={questionText} onChange={setQuestionText} busy={busy}
        onClose={()=>setQuestionOpen(false)} onSubmit={()=>submitListingIntent('question',questionText)}/>}
      {viewingRequestOpen&&<ViewingReadinessSheet readiness={viewingReadiness} facts={viewingFacts} onChange={setViewingFacts} busy={busy} onClose={()=>setViewingRequestOpen(false)} onSubmit={()=>void submitViewingReadiness()}/>}
      {actionSuccess&&<SuccessSheet message={actionSuccess.message} detail={actionSuccess.detail} onClose={()=>setActionSuccess(null)}/>}
      {webContactOpen&&<WebContactSheet value={webContact} onChange={setWebContact} onClose={()=>{setWebContactOpen(false);setPendingWebAction(null)}} onContinue={()=>{if(!webContact.email.trim()&&!webContact.phone.trim()){showToast('Укажите email или телефон');return}localStorage.setItem('property_web_contact',JSON.stringify(webContact));const next=pendingWebAction;setWebContactOpen(false);setPendingWebAction(null);if(next)void submitListingIntent(next.action,next.message,next.viewingWindows)}}/>}
      {config.marketplaceEnabled&&viewingPrompt&&initData&&<ViewingPrompt onConfirm={()=>respondViewing(viewingPrompt,'confirm')} onCancel={()=>respondViewing(viewingPrompt,'cancel')}/>}
      {toast&&<div className="toast"><Check size={17}/>{toast}</div>}
    </>;
  }

  return <div className="app">
    <header className="topbar">
      <div className="brand">
        {config.brandLogoUrl&&<img className="brandLogo" src={config.brandLogoUrl} alt="" />}
        <div><strong>{config.brandName}</strong><span>{displayTagline(config)}</span></div>
      </div>
      <div className="topActions">
        <label className="languageSelect compactLanguage" aria-label={tx('language.label')} title={tx('language.label')}>
          <select value={lang} onChange={e=>void changeLanguage(e.target.value as AppLanguage)}>{APP_LANGUAGES.map(code=><option key={code} value={code}>{code.toUpperCase()}</option>)}</select>
        </label>
        {(installPrompt||telegramInstall)&&<button className="iconBtn optionalTopAction" onClick={()=>void installApp()} aria-label="Установить приложение"><Download size={19}/></button>}
        <button className="iconBtn" onClick={()=>setJourneyOpen('profile')} aria-label="Аккаунт"><UserRound size={20}/></button>
      </div>
    </header>

    <main className="content">
      <section className="intro">
        <div className="kicker">{tx('catalog.kicker')}</div>
        <h1>{tx('catalog.title')}</h1>
        <p>{tx('catalog.updated',{count:tx('count.objects',{count:catalog.count})})}</p>
      </section>

      <div className="segment">
        {[['',tx('catalog.all')],['Venta',tx('catalog.buy')],['Alquiler',tx('catalog.rent')]].map(([value,label])=>
          <button key={value} className={filters.operation===value?'active':''} onClick={()=>update({operation:value})}>{label}</button>
        )}
      </div>

      <div className="searchBox">
        <Search size={20}/>
        <input value={filters.query} onChange={e=>update({query:e.target.value})}
          placeholder={tx('catalog.searchPlaceholder')} aria-label={tx('catalog.search')}/>
        {filters.query&&<button onClick={()=>update({query:''})} aria-label={tx('common.clear')}><X size={18}/></button>}
      </div>

      <div className="quickRow" aria-label={tx('filters.areaCity')}>
        {quickHoods.map(hood=><button key={hood} className={filters.neighborhoods.includes(hood)?'chip active':'chip'}
          onClick={()=>toggleNeighborhood(hood)}>{prettyHood(hood)}</button>)}
      </div>

      <div className="resultHeader">
        <div className="resultCount"><strong>{results.length}</strong><span> {tx('count.objects',{count:results.length}).replace(/^\d+\s*/, '')}</span></div>
        <div className="resultActions">
          <button className={activeFilterCount(filters)>0?'filterPrimary hasFilters':'filterPrimary'} onClick={()=>setFiltersOpen(true)}>
            <SlidersHorizontal size={16}/> {tx('catalog.filters')}
            {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
          </button>
          <select className="sortSelect" value={filters.sort} onChange={e=>update({sort:e.target.value})} aria-label={tx('catalog.sort')}>
            <option value="recommended">{tx('catalog.sortRecommended')}</option>
            <option value="price_asc">{tx('catalog.sortPriceAsc')}</option>
            <option value="price_desc">{tx('catalog.sortPriceDesc')}</option>
            <option value="area_desc">{tx('catalog.sortAreaDesc')}</option>
          </select>
          <div className="viewToggle" aria-label={tx('catalog.view')}>
            <button className={viewMode==='list'?'active':''} onClick={()=>setViewMode('list')} aria-label={tx('catalog.list')}><List size={16}/><span>{tx('catalog.list')}</span></button>
            <button className={viewMode==='map'?'active':''} onClick={()=>setViewMode('map')} aria-label={tx('catalog.map')}><MapIcon size={16}/><span>{tx('catalog.map')}</span></button>
          </div>
        </div>
      </div>
      {activeFilterCount(filters)>0&&<div className="activeSummary">
        <span>{tx('count.activeFilters',{count:activeFilterCount(filters)})}</span>
        <button onClick={()=>{setFilters(DEFAULT_FILTERS);setLaunchCodes(null);searchStarted.current=false}}>{tx('catalog.resetAll')}</button>
      </div>}

      <section className="cards">
        {results.map((item,index)=><React.Fragment key={listingKey(item)}>
          <ListingCard item={item} onOpen={()=>openListing(item)}/>
          {index===2&&config.telegramChannelUrl&&<button className="channelSubscribe catalogInterlude" onClick={openTelegramFeed}>
            <Bell size={18}/>
            <span className="channelSubscribeText"><strong>{tx('channel.title')}</strong><small>{tx('channel.subtitle',{brand:config.brandName})}</small></span>
            <span className="channelSubscribeCta">{tx('channel.cta')}</span>
          </button>}
        </React.Fragment>)}
        {results.length>0&&results.length<3&&config.telegramChannelUrl&&<button className="channelSubscribe catalogInterlude" onClick={openTelegramFeed}>
          <Bell size={18}/>
          <span className="channelSubscribeText"><strong>{tx('channel.title')}</strong><small>{tx('channel.subtitle',{brand:config.brandName})}</small></span>
          <span className="channelSubscribeCta">{tx('channel.cta')}</span>
        </button>}
        {!results.length&&<div className="emptyState">
          <div className="emptyIcon"><Search size={26}/></div>
          <h3>{tx('catalog.noMatch')}</h3>
          <p>{canSaveSearch(filters)?tx('catalog.saveHint'):tx('catalog.saveNeedCriteria')}</p>
          {canSaveSearch(filters)&&<button className="primary" onClick={()=>{setSaveScope('current');setSaveOpen(true)}}><Bell size={18}/> {tx('catalog.saveSearch')}</button>}
        </div>}
      </section>
    </main>

    {viewMode==='map'&&<div className="mapFullscreen">
      <React.Suspense fallback={<div className="mapLoading full"><div className="spinner"/><span>{tx('catalog.mapLoading')}</span></div>}>
        <CatalogMap items={results} onOpen={item=>openListing(item as Listing)} onFallback={()=>setViewMode('list')}
          initialViewport={mapViewportRef.current} onViewportChange={value=>{mapViewportRef.current=value}}/>
      </React.Suspense>
      <div className="mapTopOverlay">
        <button className="mapBackBtn" onClick={()=>setViewMode('list')}><ArrowLeft size={20}/><span>{tx('catalog.list')}</span></button>
        <div className="mapResultPill"><strong>{results.length}</strong><span> {tx('count.objects',{count:results.length}).replace(/^\d+\s*/, '')}</span></div>
        <button className="mapFilterBtn" onClick={()=>setFiltersOpen(true)}>
          <SlidersHorizontal size={18}/><span>{tx('catalog.filters')}</span>
          {activeFilterCount(filters)>0&&<b>{activeFilterCount(filters)}</b>}
        </button>
      </div>
    </div>}

    {viewMode==='list'&&canSaveSearch(filters)&&results.length>0&&
      <div className="stickySave"><button onClick={()=>{setSaveScope('current');setSaveOpen(true)}}><Bell size={18}/> {tx('catalog.saveSearch')} <span>{results.length}</span></button></div>}

    {filtersOpen&&<FilterSheet filters={filters} propertyTypes={propertyTypes} neighborhoods={catalog.neighborhoods}
      count={results.length} onClose={()=>setFiltersOpen(false)} onUpdate={update} onToggleHood={toggleNeighborhood} onToggleType={toggleType}/>}

    {saveOpen&&<SaveSheet notify={notify} setNotify={setNotify} count={results.length} busy={busy}
      authenticated={Boolean(initData||localStorage.getItem('person_session'))} webAuthEnabled={Boolean(config.webAuthEnabled)} botUsername={config.botUsername} onClose={()=>setSaveOpen(false)} onSave={saveSearch}/>}

    {journeyOpen==='profile'&&<ProfileSheet webAuthEnabled={Boolean(config.webAuthEnabled)} botUsername={config.botUsername} onClose={()=>setJourneyOpen(null)}/>}
    {journeyOpen==='messages'&&<MessagesSheet activeId={activeConversation} onActive={setActiveConversation} onClose={()=>{setJourneyOpen(null);setActiveConversation('')}}/>}
    {savedOpen&&<SavedSheet items={saved} onClose={()=>setSavedOpen(false)} onOpen={item=>{setFilters(criteriaToFilters(item.criteria));setSavedOpen(false);setViewMode('list');searchStarted.current=true;event('saved_search_opened',undefined,{saved_search_id:item.id})}} onDelete={removeSaved} onState={setSavedState}/>}
    {config.marketplaceEnabled&&viewingPrompt&&initData&&!selected&&<ViewingPrompt onConfirm={()=>respondViewing(viewingPrompt,'confirm')} onCancel={()=>respondViewing(viewingPrompt,'cancel')}/>}
    {welcomeAlerts&&<AlertWelcome onClose={()=>{localStorage.setItem('property_alerts_intro_seen',String(Date.now()));setWelcomeAlerts(false)}} onAll={()=>{localStorage.setItem('property_alerts_intro_seen',String(Date.now()));setWelcomeAlerts(false);setSaveScope('all');setSaveOpen(true)}} onCustom={()=>{localStorage.setItem('property_alerts_intro_seen',String(Date.now()));setWelcomeAlerts(false);setFiltersOpen(true)}}/>}

    {toast&&<div className="toast"><Check size={17}/>{toast}</div>}
  </div>;
}

function ListingCard({item,onOpen}:{item:Listing;onOpen:()=>void}){
  const [images,setImages]=useState<string[]>(item.images||[]);
  const [photo,setPhoto]=useState(0);
  const track=useRef<HTMLDivElement>(null);
  const pointerStart=useRef<{x:number;y:number}|null>(null);
  const pointerMoved=useRef(false);
  const loadingFull=useRef(false);
  const fullLoaded=useRef((item.images?.length||0)>=(item.photoCount||0));
  const totalPhotos=Math.max(images.length,item.photoCount||0);

  const hydrateGallery=async()=>{
    if(fullLoaded.current||loadingFull.current||totalPhotos<=images.length)return;
    loadingFull.current=true;
    try{
      const full=await api<Listing>(`/api/v1/catalog/${encodeURIComponent(listingKey(item))}`);
      if(full.images?.length){
        setImages(full.images);
        fullLoaded.current=true;
      }
    }catch{
      // Keep the lightweight preview usable and retry on a later interaction.
    }finally{
      loadingFull.current=false;
    }
  };

  const go=(next:number)=>{
    void hydrateGallery();
    const el=track.current;
    if(!el)return;
    const maxIndex=Math.max(0,images.length-1);
    const clamped=Math.max(0,Math.min(next,maxIndex));
    el.scrollTo({left:clamped*el.clientWidth,behavior:'smooth'});
    setPhoto(clamped);
  };

  const dotIndexes=(()=>{
    if(totalPhotos<=1)return [] as number[];
    const visible=Math.min(5,totalPhotos);
    const start=Math.min(Math.max(photo-Math.floor(visible/2),0),Math.max(0,totalPhotos-visible));
    return Array.from({length:visible},(_,i)=>start+i);
  })();

  return <article className="listingCard">
    <div className="cover cardCarousel">
      {images.length?
        <div ref={track} className="cardCarouselTrack" aria-label={tx('listing.photosOf',{name:item.address||item.code})}
          onPointerDown={e=>{pointerStart.current={x:e.clientX,y:e.clientY};pointerMoved.current=false;}}
          onPointerMove={e=>{
            const start=pointerStart.current;
            if(start&&(Math.abs(e.clientX-start.x)>8||Math.abs(e.clientY-start.y)>8))pointerMoved.current=true;
          }}
          onPointerUp={()=>{
            const shouldOpen=Boolean(pointerStart.current&&!pointerMoved.current);
            pointerStart.current=null; pointerMoved.current=false;
            if(shouldOpen)onOpen();
          }}
          onPointerCancel={()=>{pointerStart.current=null;pointerMoved.current=false;}}
          onScroll={e=>{
            const el=e.currentTarget;
            const width=el.clientWidth||1;
            const i=Math.max(0,Math.min(Math.round(el.scrollLeft/width),images.length-1));
            if(i!==photo)setPhoto(i);
            if(i>=1)void hydrateGallery();
          }}>
          {images.map((src,i)=><div className="cardCarouselSlide" key={`${src}-${i}`}>
            <img src={src} alt={tx('listing.photoAlt',{name:item.address||item.code,number:i+1})} loading="lazy" draggable={false}/>
          </div>)}
        </div>:
        <div className="noPhoto"><Building2/></div>}
      <span className="opBadge">{item.operation==='Venta'?tx('listing.sale'):tx('listing.rent')}</span>
      {item.photoCount>1&&<span className="photoCount">{tx('count.photos',{count:item.photoCount})}</span>}
      {images.length>1&&<>
        {photo>0&&<button type="button" className="cardCarouselArrow left" onClick={()=>go(photo-1)} aria-label={tx('listing.previousPhoto')}><ChevronLeft size={19}/></button>}
        {photo<images.length-1&&<button type="button" className="cardCarouselArrow right" onClick={()=>go(photo+1)} aria-label={tx('listing.nextPhoto')}><ChevronRight size={19}/></button>}
        <div className="cardCarouselDots" aria-hidden="true">
          {dotIndexes.map(i=><i key={i} className={i===photo?'active':''}/>)}
        </div>
      </>}
    </div>
    <button type="button" className="cardBody cardOpen" onClick={onOpen} aria-label={tx('listing.open',{name:item.address||item.code})}>
      <div className="cardPrice">{fmtPrice(item)}</div>
      <div className="cardTitle">{translateType(item.propertyType)} · {item.address||item.code}</div>
      {spec(item)&&<div className="cardSpecs">{spec(item)}</div>}
      {item.neighborhoods[0]&&<div className="cardLocation"><MapPin size={14}/>{prettyHood(item.neighborhoods[0])}</div>}
    </button>
  </article>;
}

function ListingDetail({item,busy,brandName,onBack,onAction,onGallery,onOpenOriginal,onLanguage}:{item:Listing;busy:boolean;brandName:string;onBack:()=>void;onAction:(x:string)=>void;onGallery:(index:number)=>void;onOpenOriginal:()=>void;onLanguage:(lang:AppLanguage)=>void}){
  const [photo,setPhoto]=useState(0);
  const d=item.details||{};
  const hasMap=Number.isFinite(Number(item.latitude))&&Number.isFinite(Number(item.longitude));
  const mapsStreet=(item.address||'').replace(/\s+al\s+(?=\d)/i,' ');
  const googleAddress=[mapsStreet,item.geo?.province||(item.neighborhoods?.[0]?prettyHood(item.neighborhoods[0]):''),'Argentina'].filter(Boolean).join(', ');
  const mapUrl=hasMap?`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(googleAddress)}`:'';
  const openMap=()=>{
    if(!mapUrl)return;
    if(tg?.openLink)tg.openLink(mapUrl);
    else window.open(mapUrl,'_blank','noopener,noreferrer');
  };
  const specRows:[string,string|number][]=[];
  if(d.totalAreaM2)specRows.push([tx('specs.area'),tx('specs.sqm',{value:d.totalAreaM2})]);
  if(d.coveredAreaM2&&d.coveredAreaM2!==d.totalAreaM2)specRows.push([tx('specs.coveredArea'),tx('specs.sqm',{value:d.coveredAreaM2})]);
  if(d.rooms)specRows.push([tx('specs.rooms'),d.rooms]);
  if(d.bedrooms)specRows.push([tx('specs.bedrooms'),d.bedrooms]);
  if(d.bathrooms)specRows.push([tx('specs.bathrooms'),d.bathrooms]);
  if(d.parkingSpaces!==undefined&&d.parkingSpaces!==null)specRows.push([tx('specs.parking'),d.parkingSpaces?String(d.parkingSpaces):tx('common.no')]);
  const content=localizedContent(item);
  const facts=detailFacts(item);
  const services=[...new Map((item.services||[]).map(x=>[translateService(x),x])).values()];
  const features=[...new Set([...(item.environments||[]),...(item.comforts||[]),...(item.highlightedFeatures||[])].map(translateFeature))];
  return <div className="detail">
    <div className="detailNav multilingual">
      <button className="roundBtn" onClick={onBack}><ArrowLeft size={21}/></button>
      <div className="detailCode">{item.code}</div>
      <label className="detailLanguage" aria-label={tx('language.label')} title={tx('language.label')}>
        <Languages size={16}/><select value={currentLanguage()} onChange={e=>onLanguage(e.target.value as AppLanguage)}>
          {APP_LANGUAGES.map(code=><option key={code} value={code}>{code.toUpperCase()}</option>)}
        </select>
      </label>
      <button className="roundBtn" disabled={busy} onClick={()=>onAction('share')} aria-label={tx('listing.share')}><Share2 size={19}/></button>
    </div>
    <div className="gallery" role="button" tabIndex={0}
      aria-label={`${tx('listing.allPhotos')}: ${tx('count.photos',{count:item.images.length})}`}
      onClick={()=>onGallery(photo)}
      onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onGallery(photo);}}}>
      <div className="galleryTrack" onScroll={e=>{
        const el=e.currentTarget; const i=Math.round(el.scrollLeft/el.clientWidth); if(i!==photo)setPhoto(i);
      }}>
        {(item.images.length?item.images:[null]).map((src,i)=><div className="slide" key={i}>
          {src?<img src={src} alt={tx('listing.photoAlt',{name:item.address||item.code,number:i+1})}/>:<div className="noPhoto big"><Building2/></div>}
        </div>)}
      </div>
      {item.images.length>1&&<button className="galleryCount" type="button"
        onClick={e=>{e.stopPropagation();onGallery(photo)}}
        aria-label={`${tx('listing.allPhotos')}: ${tx('count.photos',{count:item.images.length})}`}>
        {photo+1} / {item.images.length} · {tx('listing.allPhotos')}
      </button>}
    </div>
    <div className="detailBody">
      <div className="detailMeta">{item.operation==='Venta'?tx('listing.saleUpper'):tx('listing.rentUpper')} · {translateType(item.propertyType)}</div>
      <h1>{item.address||item.code}</h1>
      <div className="detailPrice">{fmtPrice(item)}</div>
      {!!specRows.length&&<div className="specGrid">
        {specRows.map(([k,v])=><div key={k}><span>{k}</span><strong>{v}</strong></div>)}
      </div>}

      {content.summary&&<section className="detailSection descriptionSection">
        <h2>{tx('listing.about')}</h2>
        <p>{content.summary}</p>
      </section>}
      {content.description&&<section className="detailSection descriptionSection fullDescriptionSection">
        <h2>{tx('listing.description')}</h2>
        {(content.fallback||content.automatic)&&<small className="translationNote">{content.fallback?tx('listing.originalSpanish'):tx('listing.autoTranslated')}</small>}
        <p>{content.description}</p>
      </section>}

      {!!facts.length&&<section className="detailSection"><h2>{tx('listing.characteristics')}</h2><div className="factsList">
        {facts.map(([k,v])=><div key={k}><span>{k}</span><strong>{v}</strong></div>)}
      </div></section>}
      {!!features.length&&<section className="detailSection"><h2>{tx('listing.features')}</h2><div className="featureList">
        {features.map(x=><span key={x}>{x}</span>)}
      </div></section>}
      {!!services.length&&<section className="detailSection"><h2>{tx('listing.services')}</h2><div className="featureList serviceList">
        {services.map(x=><span key={x}>{translateService(x)}</span>)}
      </div></section>}
      {currentLanguage()==='ru'&&!!item.notes.length&&<section className="noteBox">{item.notes.map(x=><p key={x}>{x}</p>)}</section>}

      {hasMap&&<section className="detailSection locationSection"><h2>{tx('listing.location')}</h2>
        <React.Suspense fallback={<div className="detailMapSkeleton">{tx('map.loading')}</div>}>
          <DetailMap latitude={Number(item.latitude)} longitude={Number(item.longitude)} address={item.address||item.code} onOpenExternal={openMap}/>
        </React.Suspense>
      </section>}

      <div className="detailQuickActions">
        <button onClick={()=>onAction('similar')} disabled={busy}><Search size={17}/> {tx('listing.similar')}</button>
      </div>
      <button className="sourceLink" onClick={onOpenOriginal}>
        {tx('listing.original',{brand:brandName})} <ChevronRight size={17}/>
      </button>
    </div>
    {!['paused','unavailable','reserved','rented','sold','removed'].includes(String(item.status||'active').toLowerCase())?<div className="detailActions">
      <button className="secondaryAction" disabled={busy} onClick={()=>onAction('question')}><MessageCircle size={18}/> {tx('listing.ask')}</button>
      <button className="primaryAction" disabled={busy} onClick={()=>onAction('viewing')}>{tx('listing.viewing')}</button>
    </div>:<div className="detailActions"><button className="secondaryAction" disabled>{tx('listing.unavailable')}</button><button className="primaryAction" disabled={busy} onClick={()=>onAction('similar')}>{tx('listing.similar')}</button></div>}
  </div>;
}

function FullGallery({item,initialIndex,onClose}:{item:Listing;initialIndex:number;onClose:()=>void}){
  const images=item.images||[];
  const [mode,setMode]=useState<'grid'|'viewer'>('grid');
  const [index,setIndex]=useState(Math.max(0,Math.min(initialIndex,Math.max(0,images.length-1))));
  const track=useRef<HTMLDivElement|null>(null);
  const thumbs=useRef<HTMLDivElement|null>(null);
  const grid=useRef<HTMLDivElement|null>(null);
  const alignThumb=(next:number,behavior:ScrollBehavior='smooth')=>{
    requestAnimationFrame(()=>{
      const thumb=thumbs.current?.children.item(next) as HTMLElement|null;
      thumb?.scrollIntoView({behavior,block:'nearest',inline:'center'});
    });
  };
  const go=(next:number,behavior:ScrollBehavior='smooth')=>{
    if(!images.length)return;
    const clamped=Math.max(0,Math.min(next,images.length-1));
    setIndex(clamped);
    const el=track.current;
    if(el)el.scrollTo({left:el.clientWidth*clamped,behavior});
    alignThumb(clamped,behavior);
  };
  const openViewer=(next:number)=>{
    const clamped=Math.max(0,Math.min(next,images.length-1));
    setIndex(clamped);
    setMode('viewer');
  };
  const showGrid=()=>{
    setMode('grid');
    requestAnimationFrame(()=>requestAnimationFrame(()=>{
      const tile=grid.current?.children.item(index) as HTMLElement|null;
      tile?.scrollIntoView({behavior:'auto',block:'center'});
    }));
  };
  useEffect(()=>{
    const oldBody=document.body.style.overflow;
    const oldHtml=document.documentElement.style.overflow;
    document.body.style.overflow='hidden';
    document.documentElement.style.overflow='hidden';
    return ()=>{document.body.style.overflow=oldBody;document.documentElement.style.overflow=oldHtml;};
  },[]);
  useEffect(()=>{
    if(mode!=='viewer')return;
    requestAnimationFrame(()=>requestAnimationFrame(()=>go(index,'auto')));
  },[mode]);
  if(!images.length)return null;
  if(mode==='grid'){
    return <div className="fullGallery galleryOverviewMode" role="dialog" aria-modal="true" aria-label={tx('listing.allPhotosOf',{name:item.address||item.code})}>
      <div className="galleryOverviewTop">
        <button onClick={onClose} aria-label={tx('common.close')}><X size={24}/></button>
        <div><strong>{tx('listing.allPhotos')}</strong><span>{tx('listing.choosePhoto',{count:tx('count.photos',{count:images.length})})}</span></div>
      </div>
      <div className="galleryOverviewGrid" ref={grid}>
        {images.map((src,i)=><button key={`${src}-overview-${i}`} className={i===index?'selected':''} onClick={()=>openViewer(i)} aria-label={tx('listing.openPhoto',{number:i+1})}>
          <img src={src} alt={tx('listing.photoAlt',{name:item.address||item.code,number:i+1})} loading={i<10?'eager':'lazy'}/>
          <span>{i+1}</span>
        </button>)}
      </div>
    </div>;
  }
  return <div className="fullGallery galleryViewerMode" role="dialog" aria-modal="true" aria-label={tx('listing.photosOf',{name:item.address||item.code})}>
    <div className="fullGalleryTop">
      <button onClick={showGrid} aria-label={tx('listing.allPhotos')}><ChevronLeft size={25}/></button>
      <div className="fullGalleryTitle"><strong>{index+1} / {images.length}</strong><span>{item.address||item.code}</span></div>
      <button onClick={onClose} aria-label={tx('common.close')}><X size={22}/></button>
    </div>
    <div className="fullGalleryStage">
      {index>0&&<button className="galleryArrow left" onClick={()=>go(index-1)} aria-label={tx('listing.previousPhoto')}><ChevronLeft size={28}/></button>}
      <div className="fullGalleryTrack" ref={track} onScroll={e=>{
        const el=e.currentTarget;
        const next=Math.round(el.scrollLeft/Math.max(1,el.clientWidth));
        if(next!==index&&next>=0&&next<images.length){setIndex(next);alignThumb(next);}
      }}>
        {images.map((src,i)=><div className="fullGallerySlide" key={`${src}-${i}`}>
          <img src={src} alt={tx('listing.photoAlt',{name:item.address||item.code,number:i+1})} loading={Math.abs(i-index)>2?'lazy':'eager'}/>
        </div>)}
      </div>
      {index<images.length-1&&<button className="galleryArrow right" onClick={()=>go(index+1)} aria-label={tx('listing.nextPhoto')}><ChevronRight size={28}/></button>}
    </div>
    <div className="fullGalleryThumbs" ref={thumbs}>
      {images.map((src,i)=><button key={`${src}-thumb-${i}`} className={i===index?'active':''} onClick={()=>go(i)} aria-label={tx('listing.photo',{number:i+1})}>
        <img src={src} alt="" loading="lazy"/>
        <span>{i+1}</span>
      </button>)}
    </div>
  </div>;
}

function QuestionSheet({value,onChange,busy,onClose,onSubmit}:any){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet">
      <div className="sheetHandle"/>
      <div className="sheetHead"><div><span>{tx('question.title')}</span><strong>{tx('question.subtitle')}</strong></div><button className="roundBtn" onClick={onClose} aria-label={tx('common.close')}><X size={20}/></button></div>
      <p className="sheetText">{tx('question.text')}</p>
      <textarea className="questionInput" autoFocus rows={5} maxLength={2000} value={value} onChange={e=>onChange(e.target.value)} placeholder={tx('question.placeholder')}/>
      <button className="primary full" disabled={busy||!value.trim()} onClick={onSubmit}>{busy?tx('question.sending'):tx('question.send')}</button>
    </div>
  </div>;
}

function WebContactSheet({value,onChange,onClose,onContinue}:any){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}><div className="sheet">
    <div className="sheetHandle"/><div className="sheetHead"><div><span>Контакт</span><strong>Куда ответить по объекту?</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>
    <p className="sheetText">Telegram не обязателен. Оставьте email или телефон, и запрос уйдёт так же, как из приложения.</p>
    <div className="webContactFields"><input value={value.name} onChange={e=>onChange({...value,name:e.target.value})} placeholder="Имя"/><input type="email" value={value.email} onChange={e=>onChange({...value,email:e.target.value})} placeholder="Email"/><input type="tel" value={value.phone} onChange={e=>onChange({...value,phone:e.target.value})} placeholder="Телефон / WhatsApp"/></div>
    <button className="primary full" onClick={onContinue}>Продолжить</button>
  </div></div>;
}

function SuccessSheet({message,detail,onClose}:{message:string;detail:string;onClose:()=>void}){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet successSheet">
      <div className="successIcon"><Check size={26}/></div>
      <h3>{message}</h3>
      <p>{detail}</p>
      <button className="primary full" onClick={onClose}>{tx('common.done')}</button>
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
  const commercialTypes=propertyTypes.filter((x:string)=>['Local Comercial','Local','Oficina','Edificio Comercial','Galpón','Depósito'].includes(x));
  const landTypes=propertyTypes.filter((x:string)=>['Terreno o Lote','Terreno','Campo','Finca','Cochera'].includes(x));
  return <div className="overlay filterOverlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet filterSheet">
      <div className="sheetHandle"/>
      <div className="sheetHead filterSheetHead">
        <div><span>{tx('filters.title')}</span><strong>{tx('filters.now',{count:tx('count.objects',{count})})}</strong></div>
        <div className="filterHeadActions">
          {activeFilterCount(filters)>0&&<button className="resetFiltersBtn" onClick={()=>onUpdate({...DEFAULT_FILTERS})}>{tx('filters.reset')}</button>}
          <button className="roundBtn" onClick={onClose} aria-label={tx('common.close')}><X size={20}/></button>
        </div>
      </div>
      <div className="sheetScroll">
        <section className="filterSection filterStart">
          <h3>{tx('filters.what')}</h3>
          <div className="filterModeGrid">
            {[['',tx('filters.allObjects')],['Venta',tx('catalog.buy')],['Alquiler',tx('catalog.rent')]].map(([value,label])=>
              <button key={value} className={filters.operation===value?'active':''} onClick={()=>onUpdate({operation:value})}>{label}</button>
            )}
          </div>
        </section>
        <section className="filterSection">
          <h3>{tx('filters.areaCity')} <small className="filterHint">{tx('filters.multiple')}</small></h3>
          <div className="filterSearch">
            <Search size={16}/>
            <input value={hoodQuery} onChange={e=>setHoodQuery(e.target.value)} placeholder={tx('filters.findArea')}/>
            {hoodQuery&&<button onClick={()=>setHoodQuery('')} aria-label={tx('common.clear')}><X size={15}/></button>}
          </div>
          <div className="chipsWrap">
            {visibleNeighborhoods.map((x:string)=><button key={x} className={filters.neighborhoods.includes(x)?'chip active':'chip'} onClick={()=>onToggleHood(x)}>{prettyHood(x)}</button>)}
          </div>
        </section>
        <section className="filterSection"><h3>{tx('filters.propertyType')}</h3>
          <div className="typePresetRow">
            {!!residentialTypes.length&&<button onClick={()=>onUpdate({propertyTypes:residentialTypes})}>{tx('filters.residential')}</button>}
            {!!commercialTypes.length&&<button onClick={()=>onUpdate({propertyTypes:commercialTypes})}>{tx('filters.commercial')}</button>}
            {!!landTypes.length&&<button onClick={()=>onUpdate({propertyTypes:landTypes})}>{tx('filters.landParking')}</button>}
          </div>
          <div className="chipsWrap">
            {propertyTypes.map((x:string)=><button key={x} className={filters.propertyTypes.includes(x)?'chip active':'chip'} onClick={()=>onToggleType(x)}>{translateType(x)}</button>)}
          </div>
        </section>
        <section className="filterSection"><h3>{tx('filters.price')}</h3>
          <div className="currencyTabs">
            {['USD','ARS'].map((cur:string)=><button key={cur} className={filters.budgetCurrency===cur?'active':''} onClick={()=>onUpdate({budgetCurrency:cur})}>{cur}</button>)}
          </div>
          <div className="rangeInputs">
            <input inputMode="numeric" value={filters.minBudget} onChange={e=>onUpdate({minBudget:e.target.value.replace(/\D/g,'')})} placeholder={tx('common.from')}/>
            <input inputMode="numeric" value={filters.maxBudget} onChange={e=>onUpdate({maxBudget:e.target.value.replace(/\D/g,'')})} placeholder={tx('common.to')}/>
          </div>
        </section>
        <section className="filterSection"><h3>{tx('filters.rooms')}</h3><div className="roomsRow">
          {[1,2,3,4,5].map(n=><button key={n} className={filters.rooms===n?'room active':'room'} onClick={()=>onUpdate({rooms:filters.rooms===n?null:n})}>{n}</button>)}
        </div></section>
        <section className="filterSection splitFilter">
          <div><h3>{tx('filters.bedroomsFrom')}</h3><div className="miniChoice">{[1,2,3,4].map(n=><button key={n} className={filters.bedrooms===n?'active':''} onClick={()=>onUpdate({bedrooms:filters.bedrooms===n?null:n})}>{n}+</button>)}</div></div>
          <div><h3>{tx('filters.bathroomsFrom')}</h3><div className="miniChoice">{[1,2,3].map(n=><button key={n} className={filters.bathrooms===n?'active':''} onClick={()=>onUpdate({bathrooms:filters.bathrooms===n?null:n})}>{n}+</button>)}</div></div>
        </section>
        <section className="filterSection"><h3>{tx('filters.area')}</h3><div className="rangeInputs">
          <input inputMode="numeric" value={filters.minArea} onChange={e=>onUpdate({minArea:e.target.value.replace(/\D/g,'')})} placeholder={tx('common.from')}/>
          <input inputMode="numeric" value={filters.maxArea} onChange={e=>onUpdate({maxArea:e.target.value.replace(/\D/g,'')})} placeholder={tx('common.to')}/>
        </div></section>
        <section className="filterSection"><h3>{tx('filters.amenities')}</h3><div className="chipsWrap">
          <button className={filters.parking?'chip active':'chip'} onClick={()=>onUpdate({parking:!filters.parking})}>{tx('feature.parking')}</button>
          {FEATURE_OPTIONS.filter(x=>x.key!=='cochera').map(x=><button key={x.key} className={filters.features.includes(x.key)?'chip active':'chip'} onClick={()=>toggleFeature(x.key)}>{tx(x.labelKey)}</button>)}
        </div></section>
      </div>
      <div className="sheetFooter"><button className="primary" onClick={onClose}>{tx('filters.show',{count:tx('count.objects',{count})})}</button></div>
    </div>
  </div>;
}

function SaveSheet({notify,setNotify,count,busy,authenticated,webAuthEnabled,botUsername,onClose,onSave}:any){
  const bot=botUsername?'@'+botUsername:'Telegram';
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet">
      <div className="sheetHandle"/><div className="sheetHead"><div><span>{tx('save.title')}</span><strong>{tx('save.now',{count})}</strong></div><button className="roundBtn" onClick={onClose} aria-label={tx('common.close')}><X size={20}/></button></div>
      <p className="sheetText">{tx('save.text')}</p>
      <label className="notifyToggle">
        <div><Bell size={20}/><span><strong>{tx('save.notify')}</strong><small>{tx('save.notifyHint')}</small></span></div>
        <input type="checkbox" aria-label={tx('save.notifyAction')} checked={notify} onChange={e=>setNotify(e.target.checked)}/><i/>
      </label>
      {!authenticated&&<div className="authNote">{webAuthEnabled?'Войдите по email, чтобы сохранить поиск и получать уведомления.':tx('save.auth',{bot})}</div>}
      <button className="primary full" aria-label={tx('save.button')+' · '+tx('save.now',{count})} disabled={busy||!authenticated} onClick={onSave}>{busy?tx('save.saving'):tx('save.button')}</button>
    </div>
  </div>;
}

function savedSearchLabel(criteria:Record<string,unknown>){
  const bits:string[]=[];
  if(criteria.operation)bits.push(criteria.operation==='Venta'?tx('catalog.buy'):tx('catalog.rent'));
  const types=Array.isArray(criteria.propertyTypes)?criteria.propertyTypes.map(String):[];
  if(types.length)bits.push(types.slice(0,2).map(type=>translateType(type)).join(', '));
  const hoods=Array.isArray(criteria.neighborhoods)?criteria.neighborhoods.map(String):[];
  if(hoods.length)bits.push(hoods.slice(0,2).map(prettyHood).join(', '));
  if(criteria.rooms)bits.push(tx('specs.roomsShort',{count:Number(criteria.rooms)}));
  else if(criteria.minBedrooms)bits.push(tx('specs.bedroomsShort',{count:Number(criteria.minBedrooms)})+'+');
  if(criteria.minArea)bits.push(tx('specs.sqm',{value:String(criteria.minArea)})+'+');
  const cur=typeof criteria.budgetCurrency==='string'?criteria.budgetCurrency:'USD';
  if(criteria.minBudget&&criteria.maxBudget)bits.push(`${cur} ${criteria.minBudget}–${criteria.maxBudget}`);
  else if(criteria.maxBudget)bits.push(`≤ ${cur} ${criteria.maxBudget}`);
  else if(criteria.minBudget)bits.push(`≥ ${cur} ${criteria.minBudget}`);
  const query=typeof criteria.query==='string'?criteria.query.trim():'';
  if(query)bits.push(query);
  return bits.join(' · ')||tx('saved.title');
}

function AlertWelcome({onClose,onAll,onCustom}:{onClose:()=>void;onAll:()=>void;onCustom:()=>void}){
  return <div className="alertWelcome"><button className="alertWelcomeClose" onClick={onClose} aria-label="Закрыть"><X size={17}/></button><div className="alertWelcomeIcon"><Bell size={20}/></div><div><strong>Не пропускайте новые объекты</strong><span>Можно получать все новые объявления или только те, что подходят под ваш поиск.</span></div><div className="alertWelcomeActions"><button onClick={onAll}>Все новые</button><button onClick={onCustom}>Настроить</button></div></div>
}

function ViewingReadinessSheet({readiness,facts,onChange,busy,onClose,onSubmit}:{readiness:any;facts:Record<string,any>;onChange:(x:Record<string,any>)=>void;busy:boolean;onClose:()=>void;onSubmit:()=>void}){
  const lang=currentLanguage();
  const rental=readiness?.operation==='Alquiler';
  const copy=lang==='es'?{
    kicker:'Solicitud de visita',title:'Prepará la solicitud',hint:'Completá solo lo que falta. Estos datos se reutilizan y evitan preguntas repetidas al coordinar una visita.',ready:'Datos listos para enviar',send:'Enviar solicitud',sending:'Enviando…',cancel:'Cancelar',people:'¿Cuántas personas vivirán?',pets:'¿Hay mascotas?',income:'¿Cómo acreditás ingresos?',guarantee:'Garantía',timing:'¿Cuándo pensás comprar?',financing:'Forma de compra'
  }:lang==='en'?{
    kicker:'Viewing request',title:'Prepare the request',hint:'Fill only what is missing. These details are reused so the agent does not need to ask the same questions again.',ready:'Details ready to send',send:'Send request',sending:'Sending…',cancel:'Cancel',people:'How many people will live there?',pets:'Any pets?',income:'How do you show income?',guarantee:'Guarantee',timing:'When are you planning to buy?',financing:'Purchase method'
  }:{
    kicker:'Запрос на просмотр',title:'Подготовим запрос',hint:'Заполните только то, чего не хватает. Эти данные сохранятся и избавят от повторных вопросов при следующих обращениях.',ready:'Данные готовы к отправке',send:'Отправить запрос',sending:'Отправляем…',cancel:'Отмена',people:'Сколько человек будет жить?',pets:'Есть питомцы?',income:'Как подтверждаете доход?',guarantee:'Гарантия',timing:'Когда планируете покупку?',financing:'Способ покупки'
  };
  const yesNo=lang==='es'?[['','Elegir'],['no','No'],['yes','Sí']]:lang==='en'?[['','Choose'],['no','No'],['yes','Yes']]:[['','Выбрать'],['no','Нет'],['yes','Да']];
  const income=lang==='es'?[['','Elegir'],['argentina_job','Trabajo en Argentina'],['monotributo','Monotributo'],['foreign_income','Ingresos del exterior'],['savings','Ahorros'],['other','Otro'],['unknown','Todavía no sé']]:lang==='en'?[['','Choose'],['argentina_job','Job in Argentina'],['monotributo','Monotributo'],['foreign_income','Foreign income'],['savings','Savings'],['other','Other'],['unknown','Not sure yet']]:[['','Выбрать'],['argentina_job','Работа в Аргентине'],['monotributo','Monotributo'],['foreign_income','Зарубежный доход'],['savings','Сбережения'],['other','Другое'],['unknown','Пока не знаю']];
  const guarantees=lang==='es'?[['','Elegir'],['caucion','Seguro de caución'],['propietaria','Garantía propietaria'],['other','Otra'],['need_help','Necesito ayuda'],['unknown','Todavía no sé']]:lang==='en'?[['','Choose'],['caucion','Seguro de caución'],['propietaria','Property guarantee'],['other','Other'],['need_help','I need help'],['unknown','Not sure yet']]:[['','Выбрать'],['caucion','Seguro de caución'],['propietaria','Garantía propietaria'],['other','Другое'],['need_help','Нужна помощь'],['unknown','Пока не знаю']];
  const timing=lang==='es'?[['','Elegir'],['month','En el próximo mes'],['1_3','1–3 meses'],['3_6','3–6 meses'],['later','Más adelante'],['exploring','Estoy evaluando']]:lang==='en'?[['','Choose'],['month','Within a month'],['1_3','1–3 months'],['3_6','3–6 months'],['later','Later'],['exploring','Exploring options']]:[['','Выбрать'],['month','В ближайший месяц'],['1_3','1–3 месяца'],['3_6','3–6 месяцев'],['later','Позже'],['exploring','Изучаю варианты']];
  const financing=lang==='es'?[['','Elegir'],['cash','Fondos propios'],['mortgage','Hipoteca'],['mixed','Mixto'],['unknown','Todavía no decidí']]:lang==='en'?[['','Choose'],['cash','Own funds'],['mortgage','Mortgage'],['mixed','Mixed'],['unknown','Not decided yet']]:[['','Выбрать'],['cash','Собственные средства'],['mortgage','Ипотека'],['mixed','Смешанный вариант'],['unknown','Пока не решил']];
  const set=(key:string,value:any)=>onChange({...facts,[key]:value});
  const select=(key:string,label:string,options:string[][],convert?:(v:string)=>any)=><label className="readinessField"><span>{label}</span><select value={key==='pets'?(facts[key]===true?'yes':facts[key]===false?'no':''):(facts[key]??'')} onChange={e=>set(key,convert?convert(e.target.value):e.target.value)}>{options.map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>;
  const required=rental?['occupants','pets','incomeType','guarantee']:['purchaseTiming','financingType'];
  const complete=required.every(k=>k in facts&&facts[k]!==''&&facts[k]!=null);
  const summary=required.filter(k=>k in facts&&facts[k]!==''&&facts[k]!=null);
  const labels:Record<string,string>={occupants:copy.people,pets:copy.pets,incomeType:copy.income,guarantee:copy.guarantee,purchaseTiming:copy.timing,financingType:copy.financing};
  const optionSets:Record<string,string[][]>={incomeType:income,guarantee:guarantees,purchaseTiming:timing,financingType:financing};
  const displayValue=(key:string,value:any)=>key==='pets'?(value?(lang==='es'?'Sí':lang==='en'?'Yes':'Да'):(lang==='es'?'No':lang==='en'?'No':'Нет')):(optionSets[key]?.find(([v])=>v===String(value))?.[1]||String(value));
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}><div className="sheet readinessSheet"><div className="sheetHandle"/><div className="sheetHead"><div><span>{copy.kicker}</span><strong>{copy.title}</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div><p className="sheetText">{copy.hint}</p><div className="readinessFields">{rental?<><label className="readinessField"><span>{copy.people}</span><input inputMode="numeric" type="number" min="1" max="20" value={facts.occupants??''} onChange={e=>set('occupants',e.target.value?Number(e.target.value):'')}/></label>{select('pets',copy.pets,yesNo,v=>v==='yes'?true:v==='no'?false:'')}{select('incomeType',copy.income,income)}{select('guarantee',copy.guarantee,guarantees)}</>:<>{select('purchaseTiming',copy.timing,timing)}{select('financingType',copy.financing,financing)}</>}</div>{complete&&<div className="readinessSummary"><Check size={18}/><div><strong>{copy.ready}</strong>{summary.map(k=><span key={k}>{labels[k]}: {displayValue(k,facts[k])}</span>)}</div></div>}<div className="viewingDecision"><button className="secondaryAction" onClick={onClose}>{copy.cancel}</button><button className="primaryAction" disabled={busy||!complete} onClick={onSubmit}>{busy?copy.sending:copy.send}</button></div></div></div>;
}

function ViewingPrompt({onConfirm,onCancel}:{onConfirm:()=>void;onCancel:()=>void}){
  return <div className="overlay"><div className="sheet"><div className="sheetHandle"/><div className="sheetHead"><div><span>{tx('viewing.title')}</span><strong>{tx('viewing.hint')}</strong></div></div><div className="viewingDecision"><button className="secondaryAction" onClick={onCancel}>{tx('viewing.cancel')}</button><button className="primaryAction" onClick={onConfirm}>{tx('viewing.confirm')}</button></div></div></div>;
}

function SavedSheet({items,onClose,onOpen,onDelete,onState}:{items:SavedSearch[];onClose:()=>void;onOpen:(item:SavedSearch)=>void;onDelete:(id:string)=>void;onState:(id:string,patch:{notify?:boolean;active?:boolean})=>void}){
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}>
    <div className="sheet tall">
      <div className="sheetHandle"/><div className="sheetHead"><div><span>{tx('saved.title')}</span><strong>{items.length}</strong></div><button className="roundBtn" onClick={onClose} aria-label={tx('common.close')}><X size={20}/></button></div>
      <div className="savedList">
        {items.map(item=><div className="savedItem savedCard" key={item.id}><button className="savedMain" onClick={()=>onOpen(item)}><strong>{savedSearchLabel(item.criteria)}</strong><span>{!item.active?'Поиск на паузе':item.notify?'Уведомления включены':'Сохранён без уведомлений'}</span></button><div className="savedControls"><label className="miniSwitch"><input type="checkbox" checked={item.notify&&item.active} onChange={e=>onState(item.id,{notify:e.target.checked,active:e.target.checked?true:item.active})}/><i/><span>Уведомлять</span></label><button className="moreSaved" onClick={()=>onState(item.id,{active:!item.active})}>{item.active?'Пауза':'Включить'}</button><button className="deleteSaved" aria-label="Удалить поиск" onClick={()=>onDelete(item.id)}><Trash2 size={16}/></button></div></div>)}
        {!items.length&&<div className="emptyMini"><Bookmark size={28}/><strong>{tx('saved.empty')}</strong><span>{tx('saved.emptyHint')}</span></div>}
      </div>
    </div>
  </div>;
}

function translateService(x:string){
  const key=normalizedSearch(x);
  const known:Record<string,string>={
    'agua corriente':'service.water','desague cloacal':'service.sewer','gas natural':'service.gas',
    'internet':'service.internet','luz':'service.electricity','pavimento':'service.paved',
    'telefono':'service.phone','video cable':'service.cable'
  };
  return known[key]?tx(known[key]):x;
}
function displayInfoValue(value:string){
  const key=normalizedSearch(value);
  if(['no definido','sin definir','consultar'].includes(key))return tx('common.unknown');
  if(['no','no dispone'].includes(key))return tx('common.no');
  if(['si','sí'].includes(value.trim().toLowerCase()))return tx('common.yes');
  return value.replace(/\bm2\b/gi,'m²');
}
function translateOrientation(value:string){
  const key=normalizedSearch(value);
  const known:Record<string,string>={
    norte:'orientation.north',sur:'orientation.south',este:'orientation.east',oeste:'orientation.west',
    noreste:'orientation.northeast','nordeste':'orientation.northeast',noroeste:'orientation.northwest',
    sureste:'orientation.southeast','sudeste':'orientation.southeast',suroeste:'orientation.southwest','sudoeste':'orientation.southwest'
  };
  return known[key]?tx(known[key]):displayInfoValue(value);
}
function detailFacts(item:Listing):[string,string][]{
  const info=item.additionalInfo||{};
  const labels:Record<string,string>={
    'expensas':'fact.expenses',
    'apto uso comercial':'fact.commercialUse',
    'orientacion':'fact.orientation',
    'apto credito':'fact.mortgage',
    'antiguedad':'fact.age',
  };
  const rows:[string,string][]=[];
  for(const [raw,valueRaw] of Object.entries(info)){
    const key=normalizedSearch(raw);
    if(!labels[key]||key==='orientacion'&&normalizedSearch(valueRaw)==='no definido')continue;
    let value=displayInfoValue(String(valueRaw));
    if(key==='expensas'&&/^\s*\d+(?:[.,]\d+)?\s*$/.test(String(valueRaw))){
      const n=Number(String(valueRaw).replace(',','.'));
      if(Number.isFinite(n)) value='ARS '+new Intl.NumberFormat(currentLanguage()==='ru'?'ru-RU':'es-AR',{maximumFractionDigits:0}).format(n);
    }
    if(key==='orientacion')value=translateOrientation(String(valueRaw));
    if(key==='apto credito')value=normalizedSearch(valueRaw)==='no'?tx('common.no'):normalizedSearch(valueRaw)==='si'?tx('common.yes'):value;
    const label=tx(labels[key]);
    if(!rows.some(([k])=>k===label))rows.push([label,value]);
  }
  return rows;
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
  const known:Record<string,string>={
    Departamento:'propertyType.apartment',Casa:'propertyType.house',PH:'propertyType.ph',Cochera:'propertyType.parking',
    'Local Comercial':'propertyType.commercial',Local:'propertyType.commercial','Edificio Comercial':'propertyType.building',
    'Terreno o Lote':'propertyType.land',Terreno:'propertyType.land',Campo:'propertyType.field',Finca:'propertyType.field',
    Oficina:'propertyType.office','Depósito':'propertyType.warehouse','Galpón':'propertyType.warehouse',Propiedad:'propertyType.property',Garaje:'propertyType.garage'
  };
  return known[x]?tx(known[x]):x;
}
function translateFeature(x:string){
  const key=normalizedSearch(x);
  const known:Record<string,string>={
    'balcon':'feature.balcon','aire acondicionado':'feature.ac','calefaccion':'feature.heating',
    'parrilla':'feature.parrilla','piscina':'feature.pool','pileta':'feature.pool','sum':'feature.sum',
    'laundry':'feature.laundry','lavadero':'feature.laundry','solarium':'feature.solarium','gimnasio':'feature.gym',
    'gym':'feature.gym','jardin':'feature.garden','patio':'feature.patio','terraza':'feature.terrace','baulera':'feature.storage',
    'quincho':'feature.quincho','apto credito':'feature.mortgage',
    'cocina':'feature.kitchen','comedor diario':'feature.dining','living comedor':'feature.livingDining',
    'toilette':'feature.toilette','escritorio':'feature.study','oficina':'propertyType.office','galeria':'feature.gallery',
    'biblioteca':'feature.library','cochera':'feature.parking','sala de juegos':'feature.games',
    'hidromasaje':'feature.hydromassage','vigilancia':'feature.security','vigilancia 24hs':'feature.security',
    'apto profesional':'feature.professional','amoblado':'feature.furnished',
    'ascensor':'feature.elevator','a estrenar':'feature.new','luminoso':'feature.bright','seguridad 24':'feature.security'
  };
  return known[key]?tx(known[key]):x;
}

const agentInboxMode=window.location.pathname.startsWith('/agent');
createRoot(document.getElementById('root')!).render(<React.StrictMode>{agentInboxMode?<AgentInbox/>:<App/>}</React.StrictMode>);


function ProfileSheet({onClose,webAuthEnabled,botUsername}:{onClose:()=>void;webAuthEnabled:boolean;botUsername:string}){
  const [pushKey,setPushKey]=useState(''); const [pushState,setPushState]=useState(()=>typeof Notification!=='undefined'?Notification.permission:'unsupported');
  const [facts,setFacts]=useState<Record<string,any>>({name:'',budget:'',currency:'USD',moveIn:'',termMonths:'',occupants:'',pets:'',incomeType:'',incomeAmount:'',guarantee:''});
  const [busy,setBusy]=useState(false); const [email,setEmail]=useState(()=>{try{return JSON.parse(localStorage.getItem('property_web_contact')||'{}').email||''}catch{return''}}); const [challenge,setChallenge]=useState(''); const [code,setCode]=useState(''); const [authenticated,setAuthenticated]=useState(Boolean(initData||localStorage.getItem('person_session')));
  const load=()=>api<any>(`/api/v1/profile?init_data=${encodeURIComponent(initData)}`).then(x=>{setAuthenticated(true);setFacts(v=>({...v,...x.facts,name:x.facts?.name||x.displayName||''}))}).catch(()=>setAuthenticated(Boolean(initData)));
  async function continueBrowser(){setBusy(true);try{const x=await api<{sessionToken:string}>('/api/v1/auth/device',{method:'POST',body:'{}'});localStorage.setItem('person_session',x.sessionToken);setAuthenticated(true);await load()}finally{setBusy(false)}}
  useEffect(()=>{void load();api<any>('/api/v1/config').then(x=>setPushKey(x.vapidPublicKey||'')).catch(()=>{})},[]);
  const field=(key:string,label:string,type='text')=><label className="profileField"><span>{label}</span><input type={type} value={facts[key]||''} onChange={e=>setFacts(x=>({...x,[key]:e.target.value}))}/></label>;
  async function startEmail(){setBusy(true);try{const x=await api<any>('/api/v1/auth/email/start',{method:'POST',body:JSON.stringify({email,language:currentLanguage(),init_data:initData})});setChallenge(x.challengeId)}finally{setBusy(false)}}
  async function verify(){setBusy(true);try{const x=await api<any>('/api/v1/auth/email/verify',{method:'POST',body:JSON.stringify({challenge_id:challenge,code,init_data:initData})});localStorage.setItem('person_session',x.sessionToken);setAuthenticated(true);await load()}finally{setBusy(false)}}
  async function save(){setBusy(true);try{await api('/api/v1/profile',{method:'POST',body:JSON.stringify({init_data:initData,session_token:localStorage.getItem('person_session')||'',preferred_language:currentLanguage(),facts})});onClose()}finally{setBusy(false)}}
  if(!authenticated)return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}><div className="sheet"><div className="sheetHandle"/><div className="sheetHead"><div><span>Войти</span><strong>Один аккаунт для сайта и Telegram</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div>{webAuthEnabled?<><p className="sheetText">Войдите по email. Поиски, обращения и данные профиля останутся с вами на любом устройстве.</p><div className="webContactFields"><input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email"/>{challenge&&<input inputMode="numeric" value={code} onChange={e=>setCode(e.target.value.replace(/\D/g,'').slice(0,6))} placeholder="6-значный код"/>}</div><button className="primary full" disabled={busy||!email||Boolean(challenge&&code.length!==6)} onClick={()=>void (challenge?verify():startEmail())}>{busy?'Подождите…':challenge?'Войти':'Получить код'}</button></>:<><p className="sheetText">Можно продолжить прямо в браузере. Профиль, поиски и обращения сохранятся на этом устройстве; позже их можно связать с email или Telegram.</p><button className="primary full" disabled={busy} onClick={()=>void continueBrowser()}>{busy?'Подождите…':'Продолжить в браузере'}</button>{botUsername&&<button className="secondary full" onClick={()=>window.location.href=`https://t.me/${botUsername}`}>Открыть в Telegram</button>}</>}</div></div>;
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget)onClose()}}><div className="sheet tall accountSheet"><div className="sheetHandle"/><div className="sheetHead"><div><span>Аккаунт</span><strong>{facts.name||'Ваши поиски и обращения'}</strong></div><button className="roundBtn" onClick={onClose}><X size={20}/></button></div><div className="accountNav"><button onClick={()=>void enableWebPush(pushKey).then(ok=>{setPushState(ok?'granted':Notification.permission)})}><Bell size={19}/><span><strong>{pushState==='granted'?'Уведомления включены':'Включить уведомления'}</strong><small>{pushState==='denied'?'Разрешите их в настройках браузера':'Новые варианты и ответы'}</small></span></button><button onClick={()=>window.dispatchEvent(new CustomEvent('pn:messages'))}><MessageCircle size={19}/><span><strong>Мои обращения</strong><small>Статусы, просмотры и ответы</small></span></button><button onClick={()=>window.dispatchEvent(new CustomEvent('pn:saved'))}><Bell size={19}/><span><strong>Уведомления и поиски</strong><small>Все новые или отдельные настройки</small></span></button></div><div className="profileScroll compactProfile">{field('name','Имя')}{field('email','Email','email')}{field('phone','Телефон / WhatsApp')}<details className="profileGroup"><summary>Для аренды</summary><div>{field('occupants','Сколько человек','number')}<label className="profileField"><span>Питомцы</span><select value={facts.pets===true?'yes':facts.pets===false?'no':''} onChange={e=>setFacts(x=>({...x,pets:e.target.value==='yes'?true:e.target.value==='no'?false:''}))}><option value="">Не указано</option><option value="no">Нет</option><option value="yes">Да</option></select></label><label className="profileField"><span>Доход</span><select value={facts.incomeType||''} onChange={e=>setFacts(x=>({...x,incomeType:e.target.value}))}><option value="">Не указано</option><option value="argentina_job">Работа в Аргентине</option><option value="monotributo">Monotributo</option><option value="foreign_income">Зарубежный доход</option><option value="savings">Сбережения</option><option value="other">Другое</option><option value="unknown">Пока не знаю</option></select></label><label className="profileField"><span>Гарантия</span><select value={facts.guarantee||''} onChange={e=>setFacts(x=>({...x,guarantee:e.target.value}))}><option value="">Не указано</option><option value="caucion">Seguro de caución</option><option value="propietaria">Garantía propietaria</option><option value="other">Другое</option><option value="need_help">Нужна помощь</option><option value="unknown">Пока не знаю</option></select></label></div></details><details className="profileGroup"><summary>Для покупки</summary><div><label className="profileField"><span>Когда планируете покупку</span><select value={facts.purchaseTiming||''} onChange={e=>setFacts(x=>({...x,purchaseTiming:e.target.value}))}><option value="">Не указано</option><option value="month">В ближайший месяц</option><option value="1_3">1–3 месяца</option><option value="3_6">3–6 месяцев</option><option value="later">Позже</option><option value="exploring">Изучаю варианты</option></select></label><label className="profileField"><span>Способ покупки</span><select value={facts.financingType||''} onChange={e=>setFacts(x=>({...x,financingType:e.target.value}))}><option value="">Не указано</option><option value="cash">Собственные средства</option><option value="mortgage">Ипотека</option><option value="mixed">Смешанный вариант</option><option value="unknown">Пока не решил</option></select></label></div></details></div><p className="profilePrivacy">Заполнять всё заранее не обязательно. При запросе просмотра приложение спросит только недостающие данные и сохранит их для следующих обращений. Проверка документов и подтверждение дохода — отдельный этап, если они действительно понадобятся.</p><div className="profileFooter"><button className="primary" disabled={busy} onClick={()=>void save()}>{busy?'Сохраняем…':'Сохранить'}</button></div></div></div>
}
function MessagesSheet({activeId,onActive,onClose}:{activeId:string;onActive:(id:string)=>void;onClose:()=>void}){
 const [items,setItems]=useState<any[]>([]); const [conversation,setConversation]=useState<any>(null); const [text,setText]=useState('');
 const loadList=()=>api<any>(`/api/v1/conversations?init_data=${encodeURIComponent(initData)}`).then(x=>setItems(x.items||[])).catch(()=>{});
 const loadConversation=(id:string)=>api<any>(`/api/v1/conversations/${id}?init_data=${encodeURIComponent(initData)}`).then(setConversation).catch(()=>{});
 useEffect(()=>{loadList();const timer=setInterval(loadList,5000);return()=>clearInterval(timer)},[]);
 useEffect(()=>{if(activeId){loadConversation(activeId);const timer=setInterval(()=>loadConversation(activeId),5000);return()=>clearInterval(timer)}setConversation(null)},[activeId]);
 async function send(){const body=text.trim();if(!body||!activeId)return;setText('');await api(`/api/v1/conversations/${activeId}/messages`,{method:'POST',body:JSON.stringify({init_data:initData,body,source_language:currentLanguage(),source_channel:initData?'telegram':'web'})});await loadConversation(activeId)}
 return <div className="overlay"><div className="sheet tall messagesSheet"><div className="sheetHandle"/><div className="sheetHead"><div><span>{activeId?'Обращение':'Мои обращения'}</span><strong>{conversation?.listingAddress||'Запросы по объектам'}</strong></div><button className="roundBtn" onClick={activeId?()=>onActive(''):onClose}>{activeId?<ArrowLeft size={20}/>:<X size={20}/>}</button></div>{!activeId?<div className="savedList">{items.map(x=><button className="conversationCard" key={x.id} onClick={()=>onActive(x.id)}><div><strong>{x.listingAddress||x.listingCode} {x.unreadCount>0&&<b className="unreadBadge">{x.unreadCount}</b>}</strong><span className="conversationStatus">{x.workflowLabel||'Согласовываем'}</span><span>{x.lastMessage||'Открыть обращение'}</span></div></button>)}{!items.length&&<div className="emptyMini"><MessageCircle size={28}/><strong>Пока нет обращений</strong><span>Откройте объект, задайте вопрос или запросите просмотр.</span></div>}</div>:<>{conversation?.qualificationSnapshot&&Object.keys(conversation.qualificationSnapshot).length>0&&<div className="qualificationCard"><strong>Данные, переданные по аренде</strong>{Object.entries(conversation.qualificationSnapshot).filter(([,v])=>v!==''&&v!=null).slice(0,8).map(([k,v])=><span key={k}>{k}: {String(v)}</span>)}</div>}{(conversation?.viewingRequests||[]).filter((v:any)=>v.status==='pending').slice(-1).map((v:any)=><div className="chatViewingCard" key={v.id}><strong>Запрос на просмотр отправлен</strong><span>Агент проверит объект и предложит конкретное время.</span></div>)}<div className="quickReplies">{['Когда можно посмотреть?','Какие условия аренды?','Можно с питомцем?'].map(q=><button key={q} onClick={()=>setText(q)}>{q}</button>)}</div><div className="chatThread">{(conversation?.messages||[]).map((m:any)=><div className={`chatBubble ${m.senderRole}`} key={m.id}><span>{m.senderRole==='partner'?(m.translatedBody||m.body):m.body}</span>{m.translatedBody&&m.translatedBody!==m.body&&<details><summary>Оригинал</summary><p>{m.body}</p></details>}</div>)}</div>{(conversation?.viewings||[]).filter((v:any)=>['proposed','confirmed'].includes(v.status)).slice(-1).map((v:any)=><div className="chatViewingCard" key={v.id}><strong>{v.status==='confirmed'?'Просмотр подтверждён':'Предложен просмотр'}</strong><span>{new Date(v.proposedAt).toLocaleString()}</span>{v.status==='proposed'&&<div><button onClick={()=>api(`/api/v1/viewings/${v.id}/confirm?init_data=${encodeURIComponent(initData)}`,{method:'POST'}).then(()=>loadConversation(activeId))}>Подтвердить</button><button onClick={()=>api(`/api/v1/viewings/${v.id}/cancel?init_data=${encodeURIComponent(initData)}`,{method:'POST'}).then(()=>loadConversation(activeId))}>Не подходит</button></div>}</div>)}<div className="chatComposer"><textarea rows={2} value={text} onChange={e=>setText(e.target.value)} placeholder="Напишите по-русски…"/><button onClick={()=>void send()} disabled={!text.trim()}><Send size={18}/></button></div></>}</div></div>
}
