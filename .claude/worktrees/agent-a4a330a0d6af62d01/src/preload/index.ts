import { contextBridge, ipcRenderer } from 'electron';

const api = {
  // Projects
  getProjects: () => ipcRenderer.invoke('db:getProjects'),
  createProject: (name: string, url: string) => ipcRenderer.invoke('db:createProject', name, url),
  deleteProject: (id: string) => ipcRenderer.invoke('db:deleteProject', id),

  // Scans
  getScans: (projectId: string) => ipcRenderer.invoke('db:getScans', projectId),
  createScan: (projectId: string, config: any) => ipcRenderer.invoke('scan:create', projectId, config),
  startScan: (scanId: string) => ipcRenderer.invoke('scan:start', scanId),
  stopScan: (scanId: string) => ipcRenderer.invoke('scan:stop', scanId),

  // Findings
  getFindings: (scanId: string) => ipcRenderer.invoke('db:getFindings', scanId),
  getAllFindings: () => ipcRenderer.invoke('db:getAllFindings'),
  markFalsePositive: (id: string, value: boolean) => ipcRenderer.invoke('db:markFalsePositive', id, value),

  // Proxy
  proxyStart: (port: number) => ipcRenderer.invoke('proxy:start', port),
  proxyStop: () => ipcRenderer.invoke('proxy:stop'),
  proxySetIntercept: (enabled: boolean) => ipcRenderer.invoke('proxy:setIntercept', enabled),
  proxyForward: (queueId: string, modified?: any) => ipcRenderer.invoke('proxy:forward', queueId, modified),
  proxyDrop: (queueId: string) => ipcRenderer.invoke('proxy:drop', queueId),
  proxyGetHistory: (limit: number, offset: number) => ipcRenderer.invoke('proxy:getHistory', limit, offset),
  proxyGetIntercepted: () => ipcRenderer.invoke('proxy:getIntercepted'),
  proxyClearHistory: () => ipcRenderer.invoke('proxy:clearHistory'),
  proxyExportCA: (path: string) => ipcRenderer.invoke('proxy:exportCA', path),
  proxyGetStatus: () => ipcRenderer.invoke('proxy:getStatus'),

  // Scope
  getScopeRules: () => ipcRenderer.invoke('db:getScopeRules'),
  addScopeRule: (rule: any) => ipcRenderer.invoke('db:addScopeRule', rule),
  deleteScopeRule: (id: number) => ipcRenderer.invoke('db:deleteScopeRule', id),

  // Scan from proxy history
  scanFromHistory: (historyId: number) => ipcRenderer.invoke('scan:fromHistory', historyId),

  // Repeater
  sendRequest: (method: string, url: string, headers: Record<string, string>, body: string | null) =>
    ipcRenderer.invoke('http:sendRequest', method, url, headers, body),

  // Reports
  generateReport: (scanId: string, format: string, outputPath: string) =>
    ipcRenderer.invoke('report:generate', scanId, format, outputPath),

  // Modules
  getModules: () => ipcRenderer.invoke('scan:getModules'),

  // Settings
  getSetting: (key: string) => ipcRenderer.invoke('settings:get', key),
  setSetting: (key: string, value: any) => ipcRenderer.invoke('settings:set', key, value),
  getAllSettings: () => ipcRenderer.invoke('settings:getAll'),

  // Data management
  clearAllData: () => ipcRenderer.invoke('data:clearAll'),
  clearFindings: () => ipcRenderer.invoke('data:clearFindings'),
  clearProxyHistory: () => ipcRenderer.invoke('data:clearProxyHistory'),
  clearScans: () => ipcRenderer.invoke('data:clearScans'),

  // AI Analysis
  aiIsConfigured: () => ipcRenderer.invoke('ai:isConfigured'),
  aiAnalyzeUrl: (url: string) => ipcRenderer.invoke('ai:analyzeUrl', url),
  aiAnalyzeJs: (jsUrl: string) => ipcRenderer.invoke('ai:analyzeJs', jsUrl),
  aiAnalyzeFindings: (scanId: string) => ipcRenderer.invoke('ai:analyzeFindings', scanId),
  aiAnalyzeCookies: (url: string) => ipcRenderer.invoke('ai:analyzeCookies', url),

  // Events
  onScanProgress: (callback: (data: any) => void) => {
    const listener = (_: any, data: any) => callback(data);
    ipcRenderer.on('scan:progress', listener);
    return () => ipcRenderer.removeListener('scan:progress', listener);
  },
  onScanFinding: (callback: (data: any) => void) => {
    const listener = (_: any, data: any) => callback(data);
    ipcRenderer.on('scan:finding', listener);
    return () => ipcRenderer.removeListener('scan:finding', listener);
  },
  onProxyRequest: (callback: (data: any) => void) => {
    const listener = (_: any, data: any) => callback(data);
    ipcRenderer.on('proxy:request', listener);
    return () => ipcRenderer.removeListener('proxy:request', listener);
  },
  onProxyIntercept: (callback: (data: any) => void) => {
    const listener = (_: any, data: any) => callback(data);
    ipcRenderer.on('proxy:intercept', listener);
    return () => ipcRenderer.removeListener('proxy:intercept', listener);
  },

  // Dialog
  showSaveDialog: (options: any) => ipcRenderer.invoke('dialog:showSave', options),
};

export type HackMeAPI = typeof api;

contextBridge.exposeInMainWorld('hackme', api);
