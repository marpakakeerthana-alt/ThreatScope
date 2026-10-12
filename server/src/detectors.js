const phrases=['verify your account','account suspended','urgent action','confirm your password','click here','login immediately','payment failed','claim your prize','free gift','limited time','send otp','share otp','wire transfer','gift card','crypto investment','guaranteed profit','act now','you have won','unusual activity'];
const shorteners=['bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rb.gy','shorturl.at'];
const riskyTlds=['.zip','.mov','.top','.xyz','.click','.work','.support','.country'];
function result(score,findings,summary){score=Math.max(0,Math.min(100,Math.round(score)));return{score,level:score>=80?'Critical':score>=60?'High':score>=30?'Medium':'Low',findings,summary,checkedAt:new Date().toISOString(),disclaimer:'Heuristic indicator only, not proof of malicious activity. A low score does not guarantee safety.'};}
const matches=(text,terms)=>terms.filter(t=>text.includes(t));
export function scanUrl(value=''){
 const raw=String(value).trim();let u;try{u=new URL(raw.includes('://')?raw:`https://${raw}`)}catch{return result(20,['URL could not be parsed. Check its format.'],'Unable to parse URL')}
 let s=0,f=[],h=u.hostname.toLowerCase(),all=raw.toLowerCase();
 if(u.protocol!=='https:'){s+=12;f.push('URL does not use HTTPS; this alone does not prove it is unsafe.')}
 if(u.username||u.password||all.includes('@')){s+=20;f.push('URL contains user-info or @ characters that can obscure the destination.')}
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h)){s+=22;f.push('Destination uses an IP address instead of a conventional domain name.')}
 if(h.split('.').length>=5){s+=12;f.push('Hostname has many subdomain levels.')}
 if(h.includes('xn--')){s+=24;f.push('Internationalized/punycode hostname may need lookalike-domain review.')}
 if(shorteners.includes(h)){s+=18;f.push('URL uses a shortening service; final destination is not visible here.')}
 if(riskyTlds.some(t=>h.endsWith(t))){s+=10;f.push('Domain uses a TLD that can occur in abuse; TLD alone is not evidence of a threat.')}
 const t=matches(h+u.pathname+u.search,['login','verify','account','secure','update','password','wallet','banking','gift','prize','free','support']);if(t.length>=2){s+=Math.min(20,t.length*5);f.push(`Several sensitive or lure-related terms appear: ${t.join(', ')}.`)}
 if(h.length>45){s+=8;f.push('Hostname is unusually long.')};if(!f.length)f.push('No configured URL indicators triggered. This does not guarantee the URL is safe.');return result(s,f,'URL heuristic analysis completed');
}
export function scanEmail({sender='',subject='',body=''}={}){
 let s=0,f=[],txt=`${sender} ${subject} ${body}`.toLowerCase(),d=String(sender).match(/@([^>\s]+)/);
 if(sender&&!d){s+=8;f.push('Sender field does not contain a recognizable email domain.')}
 if(d&&/^(gmail|yahoo|outlook|hotmail)\./i.test(d[1])&&/invoice|payroll|security|support|admin|ceo|urgent/i.test(subject)){s+=18;f.push('Generic mailbox domain with an authority/financial-style subject; independently verify sender.')}
 const p=matches(txt,phrases);if(p.length){s+=Math.min(40,p.length*9);f.push(`Potential social-engineering phrases: ${p.join(', ')}.`)}
 const urls=String(body).match(/https?:\/\/[^\s<>()]+/gi)||[];if(urls.length){s+=Math.min(20,urls.length*5);f.push(`${urls.length} URL(s) found in email body; review destinations before opening.`);if(urls.some(x=>scanUrl(x).score>=60)){s+=20;f.push('An embedded URL triggered multiple high-risk URL heuristics.')}}
 if(/[A-Z]{5,}/.test(subject)){s+=5;f.push('Subject contains an all-caps segment that may create urgency.')};if(!f.length)f.push('No configured email heuristics triggered. Sender authenticity was not independently verified.');return result(s,f,'Email threat analysis completed');
}
export function scanMessage(message=''){
 const t=String(message).toLowerCase();let s=0,f=[],p=matches(t,phrases);if(p.length){s+=Math.min(45,p.length*10);f.push(`Scam/social-engineering phrases: ${p.join(', ')}.`)}
 if(/\b(otp|one[- ]time password|verification code)\b/.test(t)&&/\b(send|share|tell|reply|give)\b/.test(t)){s+=25;f.push('Message appears to request a one-time code. Never share verification codes.')}
 if(/\b(guaranteed|risk[- ]free)\b/.test(t)&&/\b(profit|return|investment|money)\b/.test(t)){s+=20;f.push('Unrealistic or guaranteed financial-return language detected.')}
 if(/https?:\/\//.test(t)){s+=8;f.push('Message includes a link; inspect the destination before interacting.')};if((t.match(/!/g)||[]).length>=4){s+=5;f.push('Repeated exclamation marks may create urgency.')};if(!f.length)f.push('No configured spam/scam indicators triggered. This does not establish trustworthiness.');return result(s,f,'Message analysis completed');
}
export function scanNetwork(logs=''){
 const rows=String(logs).split(/\r?\n/).map(x=>x.trim()).filter(Boolean),data=rows.filter(x=>!/^timestamp[,;\s]/i.test(x)&&!x.startsWith('#'));let s=0,f=[];if(!data.length)return result(0,['No log rows found. Paste one event per line.'],'No network events analyzed');
 const failed=data.filter(x=>/fail|denied|blocked|unauthorized|401|403|reset/i.test(x));if(failed.length>=5){s+=25;f.push(`${failed.length} rows contain failure/denial indicators; review repeated access attempts.`)}
 const vals=data.map(r=>{const m=r.match(/\b(\d{5,})\b/g);return m?Math.max(...m.map(Number)):null}).filter(v=>v!==null);if(vals.length>=4){const avg=vals.reduce((a,b)=>a+b,0)/vals.length,out=vals.filter(v=>v>Math.max(avg*3,1000000));if(out.length){s+=20;f.push(`${out.length} unusually large numeric value(s) found; confirm they represent byte counts.`)}}
 const ips=new Set((data.join('\n').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]));if(ips.size>=20){s+=15;f.push(`${ips.size} distinct IPv4-looking addresses appear; check whether expected.`)}if(data.length>=1000){s+=10;f.push(`Large input (${data.length} rows); review event rates and time windows.`)}if(!f.length)f.push(`Analyzed ${data.length} row(s); no configured anomaly heuristic triggered. This is not a full intrusion detection system.`);return result(s,f,`Network log heuristic analysis completed (${data.length} rows)`);
}

function normalizedName(v=''){return String(v).toLowerCase().replace(/https?:\/\//g,'').replace(/^www\./,'').replace(/[^a-z0-9]/g,'')}
function editDistance(a,b){const row=Array.from({length:b.length+1},(_,i)=>i);for(let i=1;i<=a.length;i++){let prev=row[0];row[0]=i;for(let j=1;j<=b.length;j++){const old=row[j];row[j]=Math.min(row[j]+1,row[j-1]+1,prev+(a[i-1]===b[j-1]?0:1));prev=old}}return row[b.length]}
export function scanFakeBrandPage({brandName='',pageName='',url='',description=''}={}){
 let s=0,f=[];const brand=normalizedName(brandName),page=normalizedName(pageName),raw=String(url).trim();
 if(!brand||!page)return result(0,['Provide both the official brand name and the page name to compare.'],'More information required');
 if(page===brand){s+=0;f.push('Page name matches the supplied brand name; this alone does not verify ownership.')}
 else if(page.includes(brand)||brand.includes(page)){s+=12;f.push('Page name is similar to the brand name but not an exact match; verify through an official channel.')}
 else {const dist=editDistance(brand,page);const ratio=dist/Math.max(brand.length,page.length,1);if(ratio<=0.35){s+=30;f.push('Page name is a possible lookalike or misspelling of the supplied brand.')}else{s+=18;f.push('Page name differs from the supplied brand name; confirm whether the page is officially affiliated.')}}
 const text=`${pageName} ${description}`.toLowerCase();const lure=matches(text,['official support','customer care','claim reward','giveaway','free gift','verify account','limited offer','whatsapp support','contact admin','investment opportunity']);if(lure.length){s+=Math.min(24,lure.length*8);f.push(`Page contains promotional or impersonation-prone wording: ${lure.join(', ')}.`)}
 if(raw){try{const u=new URL(raw.includes('://')?raw:`https://${raw}`);if(u.protocol!=='https:'){s+=8;f.push('Page URL does not use HTTPS.')};if(u.hostname.includes('xn--')){s+=20;f.push('Page URL uses punycode, which can be used in lookalike domains.')};if(normalizedName(u.hostname).includes(brand)&&!normalizedName(u.hostname).endsWith(brand)){s+=12;f.push('Brand text appears within a longer hostname; inspect the registered domain carefully.')}}catch{s+=10;f.push('Page URL could not be parsed; verify the address manually.')}}
 if(!f.length)f.push('No configured fake-brand-page indicators triggered. Page ownership was not verified.');return result(s,f,'Fake company/brand page heuristic review completed');
}
export function scanSocialProfile({brandName='',profileName='',handle='',platform='',bio='',followers='',accountAgeDays='',verified='unknown'}={}){
 let s=0,f=[];const brand=normalizedName(brandName),profile=normalizedName(profileName),user=normalizedName(handle).replace(/^@/,'');
 if(!brand||(!profile&&!user))return result(0,['Provide the brand name and a profile name or handle.'],'More information required');
 const identity=profile||user;if(identity===brand){f.push('Profile name/handle matches the supplied brand text; this does not establish authenticity.')}else{const dist=editDistance(brand,identity),ratio=dist/Math.max(brand.length,identity.length,1);if(ratio<=0.35){s+=28;f.push('Profile name or handle is a possible lookalike/misspelling of the brand.')}else if(identity.includes(brand)||brand.includes(identity)){s+=14;f.push('Profile name or handle contains only part of the brand identity; verify affiliation.')}}
 if(/official|real|support|help|customer|admin|_official|official\d/i.test(String(handle))&&verified!=='yes'){s+=10;f.push('Handle uses an official/support-style term but verified status was not confirmed.')}
 const b=String(bio).toLowerCase(),lure=matches(b,['dm us to claim','send otp','share otp','giveaway winner','free prize','investment returns','customer support whatsapp','click the link','account recovery']);if(lure.length){s+=Math.min(30,lure.length*10);f.push(`Profile bio contains suspicious contact or lure phrases: ${lure.join(', ')}.`)}
 const age=Number(accountAgeDays);if(String(accountAgeDays).trim()!==''&&Number.isFinite(age)&&age>=0&&age<30){s+=15;f.push('Account age is reported as under 30 days; newness alone is not proof of impersonation.')}
 const count=Number(followers);if(String(followers).trim()!==''&&Number.isFinite(count)&&count<20){s+=5;f.push('Reported follower count is very low; compare with trusted account history.')}
 if(verified==='no'){s+=5;f.push('Profile is reported as not verified; many legitimate accounts are also unverified.')}
 if(!f.length)f.push('No configured fake-profile indicators triggered. Verification status and account ownership were not independently checked.');return result(s,f,`Social profile heuristic review completed${platform?` (${platform})`:''}`);
}

export function classify(type,input={}){let r;if(type==='url')r=scanUrl(input.url||'');else if(type==='email')r=scanEmail(input);else if(type==='message')r=scanMessage(input.message||'');else if(type==='network')r=scanNetwork(input.logs||'');else if(type==='brandpage')r=scanFakeBrandPage(input);else if(type==='socialprofile')r=scanSocialProfile(input);else return result(0,['Use url, email, message, network, brandpage, or socialprofile.'],'Classification not run');return{...r,type,classifier:'Explainable heuristic classifier'};}
