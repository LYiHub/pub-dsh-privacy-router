import assert from 'node:assert/strict'
import test from 'node:test'

import { apply, deterministicBlockReason, resolveConfig } from '../index.js'

const LOCAL_ROUTE = { provider: 'local-ai-test', model: 'local-model' }
const CLOUD_ROUTE = { provider: 'deepseek-official', model: 'deepseek-v4-flash' }

function userMessage(text, id = crypto.randomUUID()) {
  return {
    id,
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'user' },
  }
}

function assistantMessage(text, provider, model, id = crypto.randomUUID()) {
  return {
    id,
    role: 'assistant',
    content: [{ type: 'text', text }],
    source: { kind: 'model', provider, model },
  }
}

function classifierChunks(classification, reason = 'The request is safe for the cloud.') {
  return [
    { type: 'block-start', index: 0, blockType: 'tool-call' },
    {
      type: 'tool-call-delta',
      index: 0,
      id: 'classification',
      name: 'structured_output',
      argumentsDelta: JSON.stringify({ classification, reason }),
    },
    {
      type: 'block-end',
      index: 0,
      block: {
        type: 'tool-call',
        id: 'classification',
        name: 'structured_output',
        arguments: JSON.stringify({ classification, reason }),
      },
    },
    { type: 'finish', reason: { kind: 'tool-calls' } },
  ]
}

const CLOUD_CHUNKS = [
  { type: 'block-start', index: 0, blockType: 'text' },
  { type: 'text-delta', index: 0, text: 'cloud answer' },
  { type: 'block-end', index: 0, block: { type: 'text', text: 'cloud answer' } },
  { type: 'finish', reason: { kind: 'stop' } },
]

function context(classification = 'public', options = {}) {
  const listeners = new Map()
  const requests = []
  let originalCalls = 0

  const ctx = {
    on(event, listener) {
      listeners.set(event, listener)
    },
    llm: {
      stream(request) {
        requests.push(request)
        const downstream = async function* () {
          const chunks = request.provider === CLOUD_ROUTE.provider
            ? options.cloudChunks ?? CLOUD_CHUNKS
            : options.classifierChunks ?? classifierChunks(classification)
          yield* chunks
        }
        return listeners.get('llm/stream')(request, downstream)
      },
    },
  }

  apply(ctx, {
    cloudProvider: CLOUD_ROUTE.provider,
    cloudModel: CLOUD_ROUTE.model,
    recordSessionEvents: options.recordSessionEvents ?? true,
  })

  return {
    preStep: listeners.get('agent/pre-step'),
    request: listeners.get('agent/request'),
    stream: listeners.get('llm/stream'),
    requests,
    original: async function* () {
      originalCalls += 1
      yield { type: 'text-delta', index: 0, text: 'local answer' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    },
    originalCalls: () => originalCalls,
  }
}

function agent(history = [], seedEvents = []) {
  const events = []
  const sessionEvents = [...seedEvents]
  return {
    id: 'agent-1',
    options: LOCAL_ROUTE,
    session: {
      id: 'session-1',
      append(type, data) {
        events.push({ type, data })
        sessionEvents.push({ type, data })
      },
      deriveMessages: () => [...history],
      snapshotEvents: () => [...sessionEvents],
      get events() {
        return sessionEvents
      },
      requestHeader: () => ({ config: LOCAL_ROUTE }),
    },
    events,
  }
}

async function routeTurn(fixture, currentAgent, messages, fullHistory = messages) {
  await fixture.preStep({
    agent: currentAgent,
    messages,
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }, async () => undefined)

  const route = await fixture.request({
    agent: currentAgent,
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }, async () => LOCAL_ROUTE)

  const chunks = []
  for await (const chunk of fixture.stream({
    ...route,
    messages: fullHistory,
    system: 'private cwd: /Users/example/private-project',
    tools: [{ name: 'read_file', description: 'Read local files', parameters: {} }],
    sessionId: currentAgent.session.id,
  }, fixture.original)) chunks.push(chunk)

  return { route, chunks }
}

test('configuration fails loud and deterministic rules block credentials', () => {
  assert.throws(() => resolveConfig({ unknown: true }), /unknown privacy router config key/)
  assert.throws(
    () => resolveConfig({ trustedProviders: [], trustedProviderPrefixes: [] }),
    /cannot both be empty/,
  )

  const config = resolveConfig()
  assert.equal(config.classifierMaxTokens, 128)
  assert.equal(config.recordSessionEvents, false)
  assert.throws(() => resolveConfig({ recordSessionEvents: 'yes' }), /must be a boolean/)
  assert.equal(
    deterministicBlockReason('Use api_key=not-a-real-secret-value for the request.', config),
    'assigned-secret',
  )
  assert.equal(deterministicBlockReason('/Users/example/private/file.ts', config), 'local-path')
  assert.equal(deterministicBlockReason('/home/example/private/file.ts', config), 'local-path')
  assert.equal(deterministicBlockReason('./src/file.ts', config), undefined)
})

test('stock DSH mode routes without custom session events', async () => {
  const fixture = context('public', { recordSessionEvents: false })
  const previousUser = userMessage('Previously approved public question.', 'previous-user')
  const previousAssistant = assistantMessage(
    'Previously approved cloud answer.',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'previous-assistant',
  )
  const current = userMessage('Compare HTTP/2 and HTTP/3.', 'current')
  const history = [previousUser, previousAssistant]
  const currentAgent = agent(history, [{
    type: 'privacy-router/check-result',
    data: { decision: 'cloud', turn: 0, approvedMessageIds: [previousUser.id] },
  }])

  const result = await routeTurn(fixture, currentAgent, [current], [...history, current])

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.deepEqual(currentAgent.events, [])
  assert.deepEqual(fixture.requests[1].messages, [current])
})

test('public input switches the visible request route and streams cloud output directly', async () => {
  const fixture = context('public')
  const current = userMessage('Compare HTTP/2 and HTTP/3 using public information.', 'current')
  const privateHistory = userMessage('Private path: /Users/example/private-project', 'private-history')
  const currentAgent = agent([privateHistory])

  const result = await routeTurn(fixture, currentAgent, [current], [privateHistory, current])

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.equal(result.chunks.find(chunk => chunk.type === 'text-delta')?.text, 'cloud answer')
  assert.equal(fixture.originalCalls(), 0)

  const classifierRequest = fixture.requests[0]
  assert.equal(classifierRequest.provider, LOCAL_ROUTE.provider)
  assert.equal(classifierRequest.tools[0].name, 'structured_output')
  assert.equal(classifierRequest.maxTokens, 128)
  assert.equal(classifierRequest.reasoningEffort, 'off')
  assert.match(classifierRequest.messages[0].content[0].text, /Private path/)

  const cloudRequest = fixture.requests[1]
  assert.deepEqual(cloudRequest.messages, [current])
  assert.deepEqual(cloudRequest.tools, [])
  assert.doesNotMatch(cloudRequest.system, /Users\/example|private-project/)
  assert.equal(currentAgent.events.length, 3)
  assert.deepEqual(currentAgent.events[0], {
    type: 'privacy-router/check-start',
    data: {
      checkId: currentAgent.events[0].data.checkId,
      turn: 1,
      step: 1,
    },
  })
  assert.deepEqual(currentAgent.events[2], {
    type: 'privacy-router/cloud-dispatch',
    data: {
      checkId: currentAgent.events[0].data.checkId,
      turn: 1,
      step: 1,
      sentMessages: [{ messageId: current.id, role: 'user' }],
      withheldMessages: [{ messageId: privateHistory.id, role: 'user' }],
      contextTruncated: false,
      toolsIncluded: false,
    },
  })
  assert.deepEqual(currentAgent.events[1], {
    type: 'privacy-router/check-result',
    data: {
      checkId: currentAgent.events[0].data.checkId,
      turn: 1,
      step: 1,
      classification: 'public',
      method: 'model',
      decision: 'cloud',
      provider: CLOUD_ROUTE.provider,
      model: CLOUD_ROUTE.model,
      evaluatedMessageIds: [current.id],
      approvedMessageIds: [current.id],
      classifier: {
        finish: 'tool-calls',
        output: 'tool-call structured_output:\n{"classification":"public","reason":"The request is safe for the cloud."}',
        reason: 'The request is safe for the cloud.',
      },
      durationMs: currentAgent.events[1].data.durationMs,
    },
  })
  assert.equal(Number.isSafeInteger(currentAgent.events[1].data.durationMs), true)
  assert.doesNotMatch(JSON.stringify(currentAgent.events), /HTTP\/2|private-project/)
})

test('resolves references locally while sending only previously approved cloud context', async () => {
  const fixture = context('public')
  const priorPublic = userMessage('HTTP/3 uses QUIC.', 'prior-public')
  const priorCloud = assistantMessage(
    'That usually improves loss isolation.',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'prior-cloud-answer',
  )
  const priorPrivate = userMessage('Private path: /Users/example/private-project', 'prior-private')
  const priorLocal = assistantMessage(
    'The local project contains credentials.',
    LOCAL_ROUTE.provider,
    LOCAL_ROUTE.model,
    'prior-local-answer',
  )
  const current = userMessage('Compare that with HTTP/2.', 'current-reference')
  const currentAgent = agent(
    [priorPublic, priorCloud, priorPrivate, priorLocal],
    [
      {
        type: 'privacy-router/check-result',
        data: { turn: 1, decision: 'cloud', approvedMessageIds: [priorPublic.id] },
      },
      {
        type: 'assistant/message',
        data: { turn: 1, step: 1, message: priorCloud },
      },
    ],
  )

  await routeTurn(fixture, currentAgent, [current])

  const classifierPrompt = fixture.requests[0].messages[0].content[0].text
  assert.match(classifierPrompt, /HTTP\/3 uses QUIC/)
  assert.match(classifierPrompt, /private-project/)
  assert.match(classifierPrompt, /"cloudSafe":true/)
  assert.match(classifierPrompt, /"cloudSafe":false/)

  const cloudRequest = fixture.requests[1]
  assert.deepEqual(cloudRequest.messages, [priorPublic, priorCloud, current])
  assert.doesNotMatch(JSON.stringify(cloudRequest), /private-project|credentials/)
  assert.deepEqual(currentAgent.events[1].data.approvedMessageIds, [current.id])
  assert.deepEqual(currentAgent.events[2].data, {
    checkId: currentAgent.events[0].data.checkId,
    turn: 1,
    step: 1,
    sentMessages: [
      { messageId: priorPublic.id, role: 'user' },
      { messageId: priorCloud.id, role: 'assistant' },
      { messageId: current.id, role: 'user' },
    ],
    withheldMessages: [
      { messageId: priorPrivate.id, role: 'user' },
      { messageId: priorLocal.id, role: 'assistant' },
    ],
    contextTruncated: false,
    toolsIncluded: false,
  })
})

test('records classifier output and terminal failure details', async t => {
  const cases = [
    {
      name: 'max tokens',
      chunks: [
        { type: 'block-start', index: 0, blockType: 'reasoning' },
        { type: 'reasoning-delta', index: 0, text: 'still deciding' },
        { type: 'finish', reason: { kind: 'max-tokens' } },
      ],
      reason: 'classifier-max-tokens',
      classifier: { finish: 'max-tokens', output: 'reasoning:\nstill deciding' },
    },
    {
      name: 'provider error',
      chunks: [{
        type: 'finish',
        reason: {
          kind: 'error',
          failure: { code: 'TRANSPORT', message: 'classifier unavailable' },
        },
      }],
      reason: 'classifier-error',
      classifier: {
        finish: 'error',
        output: '',
        error: 'TRANSPORT: classifier unavailable',
      },
    },
  ]

  for (const item of cases) {
    await t.test(item.name, async () => {
      const fixture = context('public', { classifierChunks: item.chunks })
      const currentAgent = agent()
      await routeTurn(fixture, currentAgent, [userMessage('Ambiguous standalone request')])
      assert.equal(currentAgent.events[1].data.classification, 'unknown')
      assert.equal(currentAgent.events[1].data.reason, item.reason)
      assert.deepEqual(currentAgent.events[1].data.classifier, item.classifier)
    })
  }
})

test('classifier results require a protocol-consistent terminal state', async t => {
  const completeArgs = (value = { classification: 'public', reason: 'safe' }) => JSON.stringify(value)
  const chunksFor = (args, finishKind) => {
    const chunks = [
      { type: 'block-start', index: 0, blockType: 'tool-call' },
      {
        type: 'tool-call-delta',
        index: 0,
        id: 'classification',
        name: 'structured_output',
        argumentsDelta: args,
      },
      {
        type: 'block-end',
        index: 0,
        block: { type: 'tool-call', id: 'classification', name: 'structured_output', arguments: args },
      },
    ]
    return finishKind === undefined
      ? chunks
      : [...chunks, { type: 'finish', reason: { kind: finishKind } }]
  }

  const cases = [
    {
      name: 'missing finish',
      args: completeArgs(),
      finishKind: undefined,
      reason: 'classifier-unknown',
    },
    {
      name: 'stop finish',
      args: completeArgs(),
      finishKind: 'stop',
      reason: 'classifier-unknown',
    },
    {
      name: 'unknown finish',
      args: completeArgs(),
      finishKind: 'unexpected',
      reason: 'classifier-unknown',
    },
    {
      name: 'tool-calls with trailing junk',
      args: `${completeArgs()} trailing junk`,
      finishKind: 'tool-calls',
      reason: 'classifier-unknown',
    },
    {
      name: 'tool-calls with additional field',
      args: completeArgs({ classification: 'public', reason: 'safe', extra: true }),
      finishKind: 'tool-calls',
      reason: 'classifier-unknown',
    },
    {
      name: 'tool-calls with invalid classification',
      args: completeArgs({ classification: 'Public', reason: 'safe' }),
      finishKind: 'tool-calls',
      reason: 'classifier-unknown',
    },
    {
      name: 'tool-calls with empty reason',
      args: completeArgs({ classification: 'public', reason: '   ' }),
      finishKind: 'tool-calls',
      reason: 'classifier-unknown',
    },
    {
      name: 'tool-calls with array payload',
      args: JSON.stringify([{ classification: 'public', reason: 'safe' }]),
      finishKind: 'tool-calls',
      reason: 'classifier-unknown',
    },
    {
      name: 'max-tokens with complete JSON',
      args: completeArgs(),
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with complete JSON and trailing junk',
      args: `${completeArgs()} trailing junk`,
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with closed reason and object suffix',
      args: '{"classification":"public","reason":"safe"}',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with closed reason and another field',
      args: '{"classification":"public","reason":"safe","extra":true',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with raw control character',
      args: '{"classification":"public","reason":"bad\u0000',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with dangling escape',
      args: '{"classification":"public","reason":"safe\\',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens with incomplete unicode escape',
      args: '{"classification":"public","reason":"safe\\u12',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
    {
      name: 'max-tokens truncated in another field',
      args: '{"classification":"public","other":"safe',
      finishKind: 'max-tokens',
      reason: 'classifier-max-tokens',
    },
  ]

  for (const item of cases) {
    await t.test(item.name, async () => {
      const fixture = context('unknown', {
        classifierChunks: chunksFor(item.args, item.finishKind),
      })
      const currentAgent = agent()
      const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous request')])

      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(fixture.requests.length, 1)
      assert.equal(fixture.originalCalls(), 1)
      assert.equal(currentAgent.events[1].data.classification, 'unknown')
      assert.equal(currentAgent.events[1].data.reason, item.reason)
      assert.equal(currentAgent.events[1].data.classifier.finish, item.finishKind ?? 'missing')
    })
  }
})

test('classifier rejects multiple or unexpected tool calls after tool-calls finish', async t => {
  const validArgs = JSON.stringify({ classification: 'public', reason: 'safe' })
  const toolCallChunks = (name, index = 0) => [
    { type: 'block-start', index, blockType: 'tool-call' },
    {
      type: 'tool-call-delta',
      index,
      id: `call-${index}`,
      name,
      argumentsDelta: validArgs,
    },
    {
      type: 'block-end',
      index,
      block: { type: 'tool-call', id: `call-${index}`, name, arguments: validArgs },
    },
  ]

  const cases = [
    {
      name: 'duplicate structured output calls',
      chunks: [
        ...toolCallChunks('structured_output', 0),
        ...toolCallChunks('structured_output', 1),
        { type: 'finish', reason: { kind: 'tool-calls' } },
      ],
    },
    {
      name: 'unexpected extra tool call',
      chunks: [
        ...toolCallChunks('structured_output', 0),
        ...toolCallChunks('read_file', 1),
        { type: 'finish', reason: { kind: 'tool-calls' } },
      ],
    },
  ]

  for (const item of cases) {
    await t.test(item.name, async () => {
      const fixture = context('unknown', { classifierChunks: item.chunks })
      const currentAgent = agent()
      const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous request')])

      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(currentAgent.events[1].data.classification, 'unknown')
      assert.equal(currentAgent.events[1].data.reason, 'classifier-unknown')
      assert.equal(fixture.originalCalls(), 1)
    })
  }
})

test('classifier rejects repeated finishes or chunks after a terminal finish', async t => {
  const validCall = classifierChunks('public', 'safe').filter(chunk => chunk.type !== 'finish')
  const lateToolCall = {
    type: 'tool-call-delta',
    index: 0,
    id: 'classification',
    name: 'structured_output',
    argumentsDelta: '',
  }
  const cases = [
    {
      name: 'error finish followed by tool-calls finish',
      chunks: [
        ...validCall,
        { type: 'finish', reason: { kind: 'error', failure: { code: 'EARLIER', message: 'failed' } } },
        { type: 'finish', reason: { kind: 'tool-calls' } },
      ],
    },
    {
      name: 'tool-calls finish followed by another tool call chunk',
      chunks: [
        ...validCall,
        { type: 'finish', reason: { kind: 'tool-calls' } },
        lateToolCall,
      ],
    },
  ]

  for (const item of cases) {
    await t.test(item.name, async () => {
      const fixture = context('unknown', { classifierChunks: item.chunks })
      const currentAgent = agent()
      const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous request')])

      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(currentAgent.events[1].data.classification, 'unknown')
      assert.equal(currentAgent.events[1].data.reason, 'classifier-unknown')
      assert.equal(currentAgent.events[1].data.classifier.finish, 'invalid-protocol')
      assert.equal(fixture.originalCalls(), 1)
    })
  }
})

test('recovers a complete classification when max tokens truncates only the reason', async () => {
  const fixture = context('unknown', {
    classifierChunks: [
      {
        type: 'tool-call-delta',
        index: 0,
        id: 'classification',
        name: 'structured_output',
        argumentsDelta: '{"classification":"public","reason":"This public request',
      },
      { type: 'finish', reason: { kind: 'max-tokens' } },
    ],
  })
  const current = userMessage('Compare HTTP/2 and HTTP/3.', 'truncated-reason')
  const currentAgent = agent()

  const result = await routeTurn(fixture, currentAgent, [current])

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.equal(currentAgent.events[1].data.classification, 'public')
  assert.deepEqual(currentAgent.events[1].data.classifier, {
    finish: 'max-tokens',
    output: 'tool-call structured_output:\n{"classification":"public","reason":"This public request',
    reason: 'This public request',
    reasonTruncated: true,
  })
})

test('does not recover a max-token classification from another truncated field', async () => {
  const fixture = context('unknown', {
    classifierChunks: [
      {
        type: 'tool-call-delta',
        index: 0,
        id: 'classification',
        name: 'structured_output',
        argumentsDelta: '{"classification":"public","other":"not the required reason',
      },
      { type: 'finish', reason: { kind: 'max-tokens' } },
    ],
  })
  const currentAgent = agent()

  const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous request')])

  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(currentAgent.events[1].data.classification, 'unknown')
  assert.equal(currentAgent.events[1].data.reason, 'classifier-max-tokens')
})

test('provider retry reuses one privacy decision and sanitized cloud candidate', async () => {
  const fixture = context('public')
  const current = userMessage('Compare HTTP/2 and HTTP/3 using public information.', 'current')
  const privateHistory = userMessage('Private path: /Users/example/private-project', 'private-history')
  const currentAgent = agent()

  await fixture.preStep({
    agent: currentAgent,
    messages: [current],
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }, async () => undefined)

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const route = await fixture.request({
      agent: currentAgent,
      turn: 1,
      step: 1,
      signal: new AbortController().signal,
    }, async () => LOCAL_ROUTE)
    assert.deepEqual(route, { ...CLOUD_ROUTE, maxTokens: 8_192 })

    for await (const _chunk of fixture.stream({
      ...route,
      messages: [privateHistory, current],
      system: 'private cwd: /Users/example/private-project',
      tools: [{ name: 'read_file', description: 'Read local files', parameters: {} }],
      sessionId: currentAgent.session.id,
    }, fixture.original)) {}
  }

  assert.equal(currentAgent.events.length, 4)
  assert.equal(
    currentAgent.events.filter(event => event.type === 'privacy-router/cloud-dispatch').length,
    2,
  )
  assert.equal(fixture.requests.length, 3)
  for (const cloudRequest of fixture.requests.slice(1)) {
    assert.deepEqual(cloudRequest.messages, [current])
    assert.deepEqual(cloudRequest.tools, [])
  }
})

test('tool continuation reuses the privacy decision for the whole user turn', async () => {
  const fixture = context('sensitive')
  const currentAgent = agent()

  await fixture.preStep({
    agent: currentAgent,
    messages: [userMessage('Analyze the named local project')],
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }, async () => undefined)
  await fixture.request({
    agent: currentAgent,
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }, async () => LOCAL_ROUTE)

  await fixture.preStep({
    agent: currentAgent,
    messages: [{
      id: 'tool-result',
      role: 'user',
      content: [{ type: 'tool-result', toolCallId: 'read-1', content: [] }],
      source: { kind: 'tool', callId: 'read-1' },
    }],
    turn: 1,
    step: 2,
    signal: new AbortController().signal,
  }, async () => undefined)
  const route = await fixture.request({
    agent: currentAgent,
    turn: 1,
    step: 2,
    signal: new AbortController().signal,
  }, async () => LOCAL_ROUTE)

  assert.deepEqual(route, LOCAL_ROUTE)
  assert.equal(currentAgent.events.length, 2)
})

test('sensitive input stays on the local route without a cloud request', async () => {
  const fixture = context('public')
  const currentAgent = agent()
  const current = userMessage('Review api_key=not-a-real-secret-value')
  const result = await routeTurn(
    fixture,
    currentAgent,
    [current],
  )

  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(result.chunks.find(chunk => chunk.type === 'text-delta')?.text, 'local answer')
  assert.equal(fixture.originalCalls(), 1)
  assert.equal(fixture.requests.length, 0)
  assert.deepEqual(currentAgent.events[1].data, {
    checkId: currentAgent.events[0].data.checkId,
    turn: 1,
    step: 1,
    classification: 'sensitive',
    method: 'deterministic',
    decision: 'local',
    reason: 'assigned-secret',
    provider: LOCAL_ROUTE.provider,
    model: LOCAL_ROUTE.model,
    evaluatedMessageIds: [current.id],
    durationMs: currentAgent.events[1].data.durationMs,
  })
})

test('semantic sensitive and unknown classifications stay local', async t => {
  for (const classification of ['sensitive', 'unknown']) {
    await t.test(classification, async () => {
      const fixture = context(classification)
      const currentAgent = agent()
      const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous standalone request')])

      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(result.chunks.find(chunk => chunk.type === 'text-delta')?.text, 'local answer')
      assert.equal(fixture.requests.length, 1)
      assert.equal(currentAgent.events[1].data.classification, classification)
      assert.equal(currentAgent.events[1].data.decision, 'local')
      assert.equal(currentAgent.events[1].data.provider, LOCAL_ROUTE.provider)
      assert.equal(currentAgent.events[1].data.model, LOCAL_ROUTE.model)
    })
  }
})

test('cloud tool calls are rejected instead of executing local tools', async () => {
  const fixture = context('public', {
    cloudChunks: [
      { type: 'block-start', index: 0, blockType: 'tool-call' },
      {
        type: 'tool-call-delta',
        index: 0,
        id: 'unsafe',
        name: 'read_file',
        argumentsDelta: '{"path":"secret"}',
      },
      { type: 'finish', reason: { kind: 'tool-calls' } },
    ],
  })

  const result = await routeTurn(fixture, agent(), [userMessage('Public question')])

  assert.equal(result.chunks.some(chunk => chunk.type === 'tool-call-delta'), false)
  assert.deepEqual(result.chunks.at(-1), {
    type: 'finish',
    reason: {
      kind: 'error',
      failure: {
        code: 'PRIVACY_ROUTER_CLOUD_TOOL_CALL',
        message: 'privacy-router: cloud responses cannot call local tools',
      },
    },
  })
})
