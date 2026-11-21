import {test} from 'node:test';
import assert from 'node:assert/strict';
import {initialTarget, prepareTarget} from './startup.mjs';

test('uses the existing blank tab and rejects missing or ambiguous pages', () => {
  const page = {type: 'page', url: 'about:blank', webSocketDebuggerUrl: 'ws://localhost/page'};
  assert.equal(initialTarget([page, {type: 'background_page', url: 'about:blank'}]), page);
  for (const targets of [[], [page, page], [{...page, url: 'edge://welcome'}]]) {
    assert.throws(() => initialTarget(targets), /one initial/);
  }
});

test('settles blank target before stopping its initial load; never navigates', async () => {
  const methods = [];
  const call = async method => {
    methods.push(method);
    return method === 'Runtime.evaluate' ? {result: {value: JSON.stringify({url: 'about:blank', readyState: 'complete'})}} : {};
  };
  const document = await prepareTarget(call, fn => fn());
  assert.equal(document.url, 'about:blank');
  assert.deepEqual(methods, ['Page.enable', 'Runtime.evaluate', 'Page.stopLoading']);
});

test('rejects loading or redirected startup instead of retrying a target request', async () => {
  for (const value of [{url: 'about:blank', readyState: 'loading'}, {url: 'edge://welcome', readyState: 'complete'}]) {
    const methods = [];
    const call = async method => { methods.push(method); return {result: {value: JSON.stringify(value)}}; };
    await assert.rejects(prepareTarget(call, fn => fn()), /not ready/);
    assert.equal(methods.includes('Page.navigate'), false);
    assert.equal(methods.includes('Page.stopLoading'), false);
  }
});
