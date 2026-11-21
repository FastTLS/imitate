// Settle the newly created blank target before its single measured navigation.
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
