import express from 'express';import cors from 'cors';import dotenv from 'dotenv';import mongoose from 'mongoose';
import {scanUrl,scanEmail,scanMessage,scanNetwork,scanFakeBrandPage,scanSocialProfile,classify} from './detectors.js';import Scan from './models/Scan.js';
dotenv.config();const app=express(),PORT=process.env.PORT||5000;app.use(cors({origin:process.env.CLIENT_ORIGIN||true}));app.use(express.json({limit:'1mb'}));let connected=false;
if(process.env.MONGODB_URI)mongoose.connect(process.env.MONGODB_URI).then(()=>{connected=true;console.log('MongoDB connected')}).catch(e=>console.warn('MongoDB unavailable; scans work without history:',e.message));
async function save(type,input,result){if(!connected)return;try{await Scan.create({type,input:JSON.stringify(input).slice(0,4000),result})}catch(e){console.warn('History save failed:',e.message)}}
function valid(req,res,key){if(!req.body||typeof req.body[key]!=='string'||!req.body[key].trim()){res.status(400).json({error:`Please provide a non-empty "${key}" value.`});return false}return true}
app.get('/api/health',(_q,r)=>r.json({status:'ok',mongoConnected:connected}));
app.post('/api/scan/url',async(q,r)=>{if(!valid(q,r,'url'))return;let x=scanUrl(q.body.url);await save('url',q.body,x);r.json(x)});
app.post('/api/scan/email',async(q,r)=>{let{sender='',subject='',body=''}=q.body||{};if(![sender,subject,body].some(x=>typeof x==='string'&&x.trim()))return r.status(400).json({error:'Enter sender, subject, or email body.'});let x=scanEmail({sender,subject,body});await save('email',{sender,subject,body},x);r.json(x)});
app.post('/api/scan/message',async(q,r)=>{if(!valid(q,r,'message'))return;let x=scanMessage(q.body.message);await save('message',q.body,x);r.json(x)});
app.post('/api/scan/network',async(q,r)=>{if(!valid(q,r,'logs'))return;let x=scanNetwork(q.body.logs);await save('network',{logs:q.body.logs.slice(0,4000)},x);r.json(x)});
app.post('/api/scan/brandpage',async(q,r)=>{let x=scanFakeBrandPage(q.body||{});await save('brandpage',q.body||{},x);r.json(x)});
app.post('/api/scan/socialprofile',async(q,r)=>{let x=scanSocialProfile(q.body||{});await save('socialprofile',q.body||{},x);r.json(x)});
app.post('/api/classify',async(q,r)=>{let{type,input}=q.body||{},x=classify(type,input||{});await save(type||'unknown',input||{},x);r.json(x)});
app.get('/api/history',async(_q,r)=>{if(!connected)return r.json({items:[],persistence:false,message:'MongoDB not connected; history is not saved.'});try{r.json({items:await Scan.find().sort({createdAt:-1}).limit(30).lean(),persistence:true})}catch{r.json({items:[],persistence:false})}});
app.use((e,_q,r,_n)=>{console.error(e);r.status(500).json({error:'Unexpected server error.'})});app.listen(PORT,()=>console.log(`ThreatScope API running on http://localhost:${PORT}`));
