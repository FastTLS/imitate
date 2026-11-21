// Settle the newly created blank target before its single measured navigation.
export function captureMode(browser) {
  if (browser === 'edge') return {name: 'headed-offscreen-software', flags: ['--disable-gpu']};
  if (browser === 'chrome') return {name: 'headed-minimized', flags: ['--start-minimized']};
  throw Error('Unsupported browser capture mode');
}

export function initialTarget(targets) {
  const pages = targets.filter(target => target.type === 'page' && target.url === 'about:blank');
  if (pages.length !== 1 || !pages[0].webSocketDebuggerUrl) throw Error('Expected one initial blank browser page');
  return pages[0];
}

export async function prepareTarget(call, ready) {
  await call('Page.enable');
  const document = await ready(async () => {
    const result = await call('Runtime.evaluate', {
      expression: 'JSON.stringify({url:location.href,readyState:document.readyState})',
      returnByValue: true,
    });
    if (result.exceptionDetails) throw Error('Cannot inspect initial browser document');
    const value = JSON.parse(result.result.value);
    if (value.url !== 'about:blank' || value.readyState !== 'complete') throw Error('Initial blank document is not ready');
    return value;
  });
  await call('Page.stopLoading');
  return document;
}
