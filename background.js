chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'saveCreds',
    title: 'Autofill Helper: 保存此站点凭据…',
    contexts: ['page']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'saveCreds') return;
  const url = new URL(tab.url);
  const domain = url.hostname;
  chrome.runtime.openOptionsPage();
  // 把域名临时放到 session 里，options 页可读取并预填
  await chrome.storage.session.set({ lastDomain: domain });
});
