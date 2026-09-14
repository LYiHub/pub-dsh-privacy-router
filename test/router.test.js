import assert from 'node:assert/strict'
import test from 'node:test'

import { apply, deterministicBlockReason, resolveConfig } from '../index.js'

const LOCAL_ROUTE = { provider: 'local-ai-test', model: 'local-model' }
const CLOUD_ROUTE = { provider: 'deepseek-official', model: 'deepseek-v4-flash' }

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function userMessage(text, id = crypto.randomUUID(), extra = {}) {
  return {
    id,
    ...extra,
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'user', ...extra.source },
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

function nerChunks(entities = []) {
  const args = JSON.stringify({ coverageComplete: true, entities })
  return [
    { type: 'block-start', index: 0, blockType: 'tool-call' },
    {
      type: 'tool-call-delta',
      index: 0,
      id: 'ner',
      name: 'structured_ner_output',
      argumentsDelta: args,
    },
    {
      type: 'block-end',
      index: 0,
      block: { type: 'tool-call', id: 'ner', name: 'structured_ner_output', arguments: args },
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
    ...(options.userQuestions ? { userQuestions: options.userQuestions } : {}),
    llm: {
      stream(request) {
        requests.push(request)
        const downstream = async function* () {
          const chunks = request.provider === CLOUD_ROUTE.provider
            ? options.cloudChunks ?? CLOUD_CHUNKS
            : request.tools?.[0]?.name === 'structured_ner_output'
              ? (typeof options.nerChunks === 'function'
                ? options.nerChunks(request)
                : options.nerChunks ?? nerChunks([]))
              : (typeof options.classifierChunks === 'function'
                ? options.classifierChunks(request)
                : options.classifierChunks ?? classifierChunks(classification))
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
    ...(options.config ?? {}),
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

function localRequests(fixture) {
  return fixture.requests.filter(request => request.provider === LOCAL_ROUTE.provider)
}

function nerRequests(fixture) {
  return localRequests(fixture).filter(
    request => request.tools?.[0]?.name === 'structured_ner_output',
  )
}

function classifierRequests(fixture) {
  return localRequests(fixture).filter(
    request => request.tools?.[0]?.name === 'structured_output',
  )
}

function cloudRequests(fixture) {
  return fixture.requests.filter(request => request.provider === CLOUD_ROUTE.provider)
}

function agent(history = [], seedEvents = [], sessionId = 'session-1') {
  const events = []
  const sessionEvents = [...seedEvents]
  return {
    id: 'agent-1',
    options: LOCAL_ROUTE,
    session: {
      id: sessionId,
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

function cloudAgent(history = [], seedEvents = [], sessionId = 'session-1') {
  const selected = agent(history, seedEvents, sessionId)
  selected.options = CLOUD_ROUTE
  selected.session.requestHeader = () => ({ config: CLOUD_ROUTE })
  return selected
}

async function routeTurn(fixture, currentAgent, messages, fullHistory = messages, streamOptions = {}, turn = 1) {
  const {
    nextRoute = LOCAL_ROUTE,
    original: originalGenerator = fixture.original,
    ...rawStreamOptions
  } = streamOptions
  await fixture.preStep({
    agent: currentAgent,
    messages,
    turn,
    step: 1,
    signal: new AbortController().signal,
  }, async () => undefined)

  const route = await fixture.request({
    agent: currentAgent,
    turn,
    step: 1,
    signal: new AbortController().signal,
  }, async () => nextRoute)

  const chunks = []
  for await (const chunk of fixture.stream({
    ...route,
    messages: fullHistory,
    system: 'private cwd: /Users/example/private-project',
    tools: [{ name: 'read_file', description: 'Read local files', parameters: {} }],
    sessionId: currentAgent.session.id,
    ...rawStreamOptions,
  }, originalGenerator)) chunks.push(chunk)

  return { route, chunks }
}

test('configuration fails loud and deterministic rules block credentials', () => {
  assert.throws(() => resolveConfig({ unknown: true }), /unknown privacy router config key/)
  assert.throws(
    () => resolveConfig({ trustedProviders: [], trustedProviderPrefixes: [] }),
    /cannot both be empty/,
  )

  const config = resolveConfig()
  assert.equal(config.classifierMaxTokens, 512)
  assert.equal(config.nerEnabled, true)
  assert.equal(config.nerConfidenceThreshold, 0.85)
  assert.equal(config.nerMaxTokens, 512)
  assert.equal(config.authorizationTtlMs, 12 * 60 * 60 * 1000)
  assert.equal(config.recordSessionEvents, false)
  assert.throws(() => resolveConfig({ nerEnabled: false }), /cannot be disabled/)
  assert.throws(() => resolveConfig({ nerConfidenceThreshold: 0.49 }), /must be a number/)
  assert.throws(() => resolveConfig({ recordSessionEvents: 'yes' }), /must be a boolean/)
  assert.equal(
    deterministicBlockReason('Use api_key=not-a-real-secret-value for the request.', config),
    'assigned-secret',
  )
  assert.equal(deterministicBlockReason('/Users/example/private/file.ts', config), 'local-path')
  assert.equal(deterministicBlockReason('/home/example/private/file.ts', config), 'local-path')
  assert.equal(deterministicBlockReason('./src/file.ts', config), undefined)
  assert.equal(deterministicBlockReason('身份证号 11010519491231002x', config), 'china-id')
  for (const text of [
    '密钥：abc123456789',
    '秘钥是 abc123456789',
    '密码：abc123456789',
    '口令=abc123456789',
    '令牌：abc123456789',
  ]) {
    assert.equal(deterministicBlockReason(text, config), 'assigned-secret', text)
  }
  assert.equal(deterministicBlockReason('请解释密钥是什么意思', config), undefined)
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
  assert.deepEqual(cloudRequests(fixture)[0].messages, [current])
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

  assert.equal(nerRequests(fixture).length, 1)
  const classifierRequest = classifierRequests(fixture)[0]
  assert.equal(classifierRequest.provider, LOCAL_ROUTE.provider)
  assert.equal(classifierRequest.tools[0].name, 'structured_output')
  assert.equal(classifierRequest.maxTokens, 512)
  assert.equal(classifierRequest.reasoningEffort, 'off')
  assert.match(classifierRequest.messages[0].content[0].text, /Private path/)

  const cloudRequest = cloudRequests(fixture)[0]
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
      placeholderCount: 0,
      authorization: { ok: true, scope: 'none', types: [] },
      rescan: 'passed',
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
      placeholderCount: 0,
      authorization: { ok: true, scope: 'none', types: [] },
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
        data: {
          turn: 1,
          decision: 'cloud',
          approvedMessageIds: [priorPublic.id],
          placeholderCount: 0,
          authorization: { ok: true, scope: 'none', types: [] },
        },
      },
      {
        type: 'assistant/message',
        data: { turn: 1, step: 1, message: priorCloud },
      },
    ],
  )

  await routeTurn(fixture, currentAgent, [current])

  const classifierPrompt = classifierRequests(fixture)[0].messages[0].content[0].text
  assert.match(classifierPrompt, /HTTP\/3 uses QUIC/)
  assert.match(classifierPrompt, /private-project/)
  assert.match(classifierPrompt, /"cloudSafe":true/)
  assert.match(classifierPrompt, /"cloudSafe":false/)

  const cloudRequest = cloudRequests(fixture)[0]
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
    placeholderCount: 0,
    authorization: { ok: true, scope: 'none', types: [] },
    rescan: 'passed',
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
      const fixture = context('public', {
        classifierChunks: request =>
          (request.tools?.[0]?.name === 'structured_output' ? item.chunks : nerChunks([])),
      })
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
        classifierChunks: request =>
          (request.tools?.[0]?.name === 'structured_output'
            ? chunksFor(item.args, item.finishKind)
            : nerChunks([])),
      })
      const currentAgent = agent()
      const result = await routeTurn(fixture, currentAgent, [userMessage('Ambiguous request')])

      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(localRequests(fixture).length, 2)
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
      const fixture = context('unknown', {
        classifierChunks: request =>
          (request.tools?.[0]?.name === 'structured_output' ? item.chunks : nerChunks([])),
      })
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
      const fixture = context('unknown', {
        classifierChunks: request =>
          (request.tools?.[0]?.name === 'structured_output' ? item.chunks : nerChunks([])),
      })
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
        classifierChunks: request =>
          (request.tools?.[0]?.name === 'structured_output'
            ? [
              {
                type: 'tool-call-delta',
                index: 0,
                id: 'classification',
                name: 'structured_output',
                argumentsDelta: '{"classification":"public","reason":"This public request',
              },
              { type: 'finish', reason: { kind: 'max-tokens' } },
            ]
            : nerChunks([])),
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
    classifierChunks: request =>
      (request.tools?.[0]?.name === 'structured_output'
        ? [
          {
            type: 'tool-call-delta',
            index: 0,
            id: 'classification',
            name: 'structured_output',
            argumentsDelta: '{"classification":"public","other":"not the required reason',
          },
          { type: 'finish', reason: { kind: 'max-tokens' } },
        ]
        : nerChunks([])),
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
  assert.equal(localRequests(fixture).length, 2)
  assert.equal(cloudRequests(fixture).length, 2)
  for (const cloudRequest of cloudRequests(fixture)) {
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
      assert.equal(localRequests(fixture).length, 2)
      assert.equal(cloudRequests(fixture).length, 0)
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

function authorizationAnswer(selected) {
  return { answers: [{ selected: [selected] }] }
}

test('NER empty result proceeds to the classifier', async () => {
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const result = await routeTurn(fixture, agent(), [userMessage('Compare HTTP and QUIC.')])
  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.deepEqual(localRequests(fixture).map(request => request.tools[0]?.name), [
    'structured_ner_output',
    'structured_output',
  ])
  assert.equal(cloudRequests(fixture).length, 1)
})

test('NER entities with low confidence fail local before classification', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([{ type: 'person', value: '张三', confidence: 0.1 }]),
  })
  const result = await routeTurn(fixture, agent(), [userMessage('请联系张三。')])
  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(nerRequests(fixture).length, 1)
  assert.equal(classifierRequests(fixture).length, 0)
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(result.chunks.at(-1).reason.kind, 'stop')
})

test('NER blocks person and quasi-identifier combinations but allows ordinary job title and public org', async t => {
  const cases = [
    [[{ type: 'person', value: '张三', confidence: 0.99 }], true],
    [[{ type: 'org', value: '公开大学', confidence: 0.99, orgScope: 'public' }], false],
    [[{ type: 'job_title', value: '经理', confidence: 0.99 }], false],
    [
      [{ type: 'person', value: '张三', confidence: 0.99 },
        { type: 'phone', value: '13800000000', confidence: 0.99 }], true,
    ],
  ]
  for (const [entities, mustStayLocal] of cases) {
    await t.test(JSON.stringify(entities), async () => {
      const normalized = Array.isArray(entities) ? entities : [entities]
      const fixture = context('public', {
        nerChunks: nerChunks(normalized.filter(entity => entity.type !== 'phone')),
        userQuestions: { ask: async () => authorizationAnswer('拒绝，留在本地') },
      })
      const text = `请处理 ${normalized.map(entity => entity.value).join('，')} 这段公开信息`
      const result = await routeTurn(fixture, agent(), [userMessage(text)])
      assert.equal(result.route.provider === LOCAL_ROUTE.provider, mustStayLocal)
    })
  }
})

test('unauthorized phone remains local and does not call cloud', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => authorizationAnswer('拒绝，留在本地') },
  })
  const result = await routeTurn(fixture, agent(), [userMessage('联系 13800000000')])
  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('missing, malformed, cancelled, and thrown authorization all remain local', async t => {
  const cases = [
    ['missing', undefined],
    ['malformed', { ask: async () => ({ answers: [] }) }],
    ['cancelled', { ask: async () => { const error = new Error('cancelled'); error.code = 'CANCELLED'; throw error } }],
    ['thrown', { ask: async () => { throw new Error('dialog failed') } }],
  ]
  for (const [name, userQuestions] of cases) {
    await t.test(name, async () => {
      const fixture = context('public', { nerChunks: nerChunks([]), userQuestions })
      const result = await routeTurn(fixture, agent(), [userMessage('联系 13800000000')])
      assert.deepEqual(result.route, LOCAL_ROUTE)
      assert.equal(cloudRequests(fixture).length, 0)
    })
  }
})

test('authorization card masks phone and exposes the three required choices', async () => {
  let question
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async payload => { question = payload.questions[0]; return authorizationAnswer('拒绝，留在本地') } },
  })
  await routeTurn(fixture, agent(), [userMessage('联系 13800000000')])
  const serialized = JSON.stringify(question)
  assert.match(serialized, /138\*\*\*\*0000/)
  assert.doesNotMatch(serialized, /13800000000/)
  assert.deepEqual(question.options.map(option => option.label), [
    '允许，仅本次具体值',
    '本会话记住这些实体类别',
    '拒绝，留在本地',
  ])
})

test('once authorization sends only a phone placeholder and asks again next turn', async () => {
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => { asks += 1; return authorizationAnswer('允许，仅本次具体值') } },
  })
  const current = userMessage('联系 13800000000', 'phone-current')
  const first = await routeTurn(fixture, agent(), [current])
  assert.deepEqual(first.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  const cloud = cloudRequests(fixture)[0]
  assert.match(cloud.messages[0].content[0].text, /\[PHONE_REDACTED_1\]/)
  assert.doesNotMatch(cloud.messages[0].content[0].text, /13800000000/)
  assert.equal(asks, 1)
  // A fresh turn with the same value must request a new one-time grant.
  const secondAgent = agent()
  await routeTurn(fixture, secondAgent, [userMessage('联系 13800000000', 'phone-again')])
  assert.equal(asks, 2)
})

test('session category authorization applies to phone but not a new email category', async () => {
  const answers = [
    authorizationAnswer('本会话记住这些实体类别'),
    authorizationAnswer('拒绝，留在本地'),
  ]
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => answers[asks++] },
  })
  const currentAgent = agent()
  await routeTurn(fixture, currentAgent, [userMessage('联系 13800000000', 'phone-one')], undefined, {}, 1)
  await routeTurn(fixture, currentAgent, [userMessage('联系 13800000000', 'phone-two')], undefined, {}, 2)
  await routeTurn(fixture, currentAgent, [userMessage('联系 a@example.com', 'email-one')], undefined, {}, 3)
  assert.equal(asks, 2)
})

test('a queued cloud request is blocked after placeholder authorization expires', async () => {
  const fixture = context('public', {
    config: { authorizationTtlMs: 10 },
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => authorizationAnswer('允许，仅本次具体值') },
  })
  const currentAgent = agent()
  const current = userMessage('联系 13800000000', 'expiring-phone')

  await fixture.preStep({
    agent: currentAgent,
    messages: [current],
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
  assert.deepEqual(route, { ...CLOUD_ROUTE, maxTokens: 8_192 })

  await sleep(30)
  const chunks = []
  for await (const chunk of fixture.stream({
    ...route,
    messages: [current],
    sessionId: currentAgent.session.id,
  }, fixture.original)) chunks.push(chunk)

  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(fixture.originalCalls(), 0)
  assert.equal(chunks.at(-1).reason.failure.code, 'PRIVACY_ROUTER_AUTHORIZATION_EXPIRED')
  assert.deepEqual(currentAgent.events.at(-1), {
    type: 'privacy-router/cloud-blocked',
    data: {
      checkId: currentAgent.events[0].data.checkId,
      turn: 1,
      step: 1,
      reason: 'authorization-expired',
    },
  })
})

test('once-value authorization cannot be reused by later turns', async () => {
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => {
      asks += 1
      return authorizationAnswer('允许，仅本次具体值')
    } },
  })
  const firstUser = userMessage('联系 13800000000', 'once-phone')
  const cloudAnswer = assistantMessage(
    '已记录这个占位符问题。',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'once-cloud-answer',
  )
  const history = [firstUser]
  const currentAgent = agent(history)

  await routeTurn(fixture, currentAgent, [firstUser], history, {}, 1)
  currentAgent.session.append('assistant/message', { turn: 1, step: 1, message: cloudAnswer })
  history.push(cloudAnswer)

  const next = userMessage('请继续解释公开概念。', 'next-public')
  history.push(next)
  await routeTurn(fixture, currentAgent, [next], history, {}, 2)

  assert.equal(asks, 1)
  const secondCloudRequest = cloudRequests(fixture).at(-1)
  assert.deepEqual(secondCloudRequest.messages, [next])
  assert.doesNotMatch(JSON.stringify(secondCloudRequest), /13800000000/)
  const repeatedPhone = userMessage('联系 13800000000', 'phone-repeated')
  await routeTurn(fixture, currentAgent, [repeatedPhone], [repeatedPhone], {}, 3)
  assert.equal(asks, 2)
})

test('session category history requires the in-memory sanitized user message after restart', async () => {
  const phoneUser = userMessage('联系 13800000000', 'session-phone')
  const cloudAnswer = assistantMessage(
    '这是公开回复。',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'session-cloud-answer',
  )
  const next = userMessage('继续解释公开概念。', 'after-restart')
  const history = [phoneUser, cloudAnswer, next]
  const authorizedAt = Date.now()
  const expiresAt = authorizedAt + 60_000
  const seedEvents = [
    {
      type: 'privacy-router/check-result',
      data: {
        turn: 1,
        decision: 'cloud',
        approvedMessageIds: [phoneUser.id],
        placeholderCount: 1,
        eligibleEntities: [{ type: 'phone', count: 1 }],
        authorization: {
          ok: true,
          scope: 'session-category',
          types: ['phone'],
          authorizedAt,
          expiresAt,
        },
      },
    },
    { type: 'assistant/message', data: { turn: 1, step: 1, message: cloudAnswer } },
  ]

  const fixture = context('public', { nerChunks: nerChunks([]) })
  const restartedAgent = agent(history, seedEvents)
  await routeTurn(fixture, restartedAgent, [next], history, {}, 2)

  const cloudRequest = cloudRequests(fixture)[0]
  assert.deepEqual(cloudRequest.messages, [cloudAnswer, next])
  assert.doesNotMatch(JSON.stringify(cloudRequest), /13800000000/)
})

test('expired or legacy incomplete PII history grants stay out of cloud context', async () => {
  const phoneUser = userMessage('联系 13800000000', 'legacy-phone')
  const cloudAnswer = assistantMessage(
    '旧回复。',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'legacy-cloud-answer',
  )
  const current = userMessage('继续解释公开概念。', 'legacy-current')
  const history = [phoneUser, cloudAnswer, current]
  const seedEvents = [
    {
      type: 'privacy-router/check-result',
      data: { turn: 1, decision: 'cloud', approvedMessageIds: [phoneUser.id] },
    },
    { type: 'assistant/message', data: { turn: 1, step: 1, message: cloudAnswer } },
  ]
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const currentAgent = agent(history, seedEvents)

  await routeTurn(fixture, currentAgent, [current], history)

  assert.deepEqual(cloudRequests(fixture)[0].messages, [current])
})

test('expired session-category history grants stay out of cloud context', async () => {
  const phoneUser = userMessage('联系 13800000000', 'expired-session-phone')
  const cloudAnswer = assistantMessage(
    '旧回复。',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'expired-session-cloud-answer',
  )
  const current = userMessage('继续解释公开概念。', 'expired-session-current')
  const history = [phoneUser, cloudAnswer, current]
  const authorizedAt = Date.now() - 120_000
  const seedEvents = [
    {
      type: 'privacy-router/check-result',
      data: {
        turn: 1,
        decision: 'cloud',
        approvedMessageIds: [phoneUser.id],
        placeholderCount: 1,
        eligibleEntities: [{ type: 'phone', count: 1 }],
        authorization: {
          ok: true,
          scope: 'session-category',
          types: ['phone'],
          authorizedAt,
          expiresAt: authorizedAt + 60_000,
        },
      },
    },
    { type: 'assistant/message', data: { turn: 1, step: 1, message: cloudAnswer } },
  ]
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const currentAgent = agent(history, seedEvents)

  await routeTurn(fixture, currentAgent, [current], history, {}, 2)

  assert.deepEqual(cloudRequests(fixture)[0].messages, [current])
  assert.doesNotMatch(JSON.stringify(cloudRequests(fixture)[0]), /13800000000/)
})

test('mixed current and historical entity authorizations use the smallest valid window', async () => {
  const answers = [
    authorizationAnswer('本会话记住这些实体类别'),
    authorizationAnswer('允许，仅本次具体值'),
  ]
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => {
      const answer = answers[asks]
      asks += 1
      return answer
    } },
  })
  const phoneUser = userMessage('联系 13800000000', 'mixed-phone')
  const cloudAnswer = assistantMessage(
    '手机号已替换。',
    CLOUD_ROUTE.provider,
    CLOUD_ROUTE.model,
    'mixed-cloud-answer',
  )
  const emailUser = userMessage('请发邮件到 a@example.com', 'mixed-email')
  const history = [phoneUser]
  const currentAgent = agent(history)

  await routeTurn(fixture, currentAgent, [phoneUser], history, {}, 1)
  const phoneAuthorization = currentAgent.events[1].data.authorization
  currentAgent.session.append('assistant/message', { turn: 1, step: 1, message: cloudAnswer })
  history.push(cloudAnswer, emailUser)
  await routeTurn(fixture, currentAgent, [emailUser], history, {}, 2)

  const resultEvent = currentAgent.events[5].data
  const dispatchEvent = currentAgent.events.at(-1).data
  assert.equal(asks, 2)
  assert.deepEqual(resultEvent.authorization.types, ['phone', 'email'])
  assert.equal(resultEvent.authorization.scope, 'once-value')
  assert.equal(resultEvent.authorization.authorizedAt, phoneAuthorization.authorizedAt)
  assert.equal(resultEvent.authorization.expiresAt, phoneAuthorization.expiresAt)
  assert.deepEqual(dispatchEvent.authorization, {
    ok: true,
    scope: 'once-value',
    types: ['phone', 'email'],
    authorizedAt: phoneAuthorization.authorizedAt,
    expiresAt: phoneAuthorization.expiresAt,
  })
  const cloudRequest = cloudRequests(fixture).at(-1)
  assert.match(JSON.stringify(cloudRequest), /\[PHONE_REDACTED_1\]|138\*\*\*0000/)
  assert.doesNotMatch(JSON.stringify(cloudRequest), /13800000000|a@example\.com/)
})

test('hard PII and sensitive entities remain local even with authorization', async () => {
  const cases = [
    ['身份证 11010519491231002X', 'id-card'],
    ['银行卡 4111111111111111', 'bank-card'],
    ['密钥 api_key=secret-value', 'assigned-secret'],
    ['/Users/example/private.txt', 'local-path'],
    ['客户内部项目 AlphaRoadmap', 'custom-sensitive-term'],
  ]
  for (const [text] of cases) {
    const fixture = context('public', {
      config: { customSensitiveTerms: ['AlphaRoadmap'] },
      userQuestions: { ask: async () => authorizationAnswer('允许，仅本次具体值') },
    })
    const result = await routeTurn(fixture, agent(), [userMessage(text)])
    assert.deepEqual(result.route, LOCAL_ROUTE, text)
    assert.equal(cloudRequests(fixture).length, 0, text)
  }
})

test('cloud projection contains only minimal user message fields', async () => {
  const current = userMessage('Public question', 'current', {
    metadata: { tenant: 'private' },
    source: { traceId: 'private-trace' },
  })
  current.content[0].annotations = [{ secretPath: '/Users/example/.env' }]
  const fixture = context('public')
  const result = await routeTurn(fixture, agent(), [current])
  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  const cloud = cloudRequests(fixture)[0]
  assert.deepEqual(cloud.messages[0], {
    id: 'current', role: 'user', content: [{ type: 'text', text: 'Public question' }], source: { kind: 'user' },
  })
})

// The NER prompt embeds the scanned text as INPUT_JSON, so a per-text mock can tell
// the current-turn scan apart from the full planned-payload scan.
function nerChunksByText(entitiesByText) {
  return request => {
    const prompt = request.messages?.[0]?.content?.[0]?.text ?? ''
    for (const [needle, entities] of entitiesByText) {
      if (prompt.includes(needle)) return nerChunks(entities)
    }
    return nerChunks([])
  }
}

test('forged history grants are blocked by the full payload NER scan', async () => {
  const historyUser = userMessage('张三的联系人名单已经整理好了。', 'forged-history')
  const current = userMessage('Compare HTTP/2 and HTTP/3 using public information.', 'forged-current')
  const history = [historyUser, current]
  const seedEvents = [{
    type: 'privacy-router/check-result',
    data: {
      turn: 1,
      decision: 'cloud',
      approvedMessageIds: [historyUser.id],
      authorization: { ok: true, scope: 'none', types: [] },
    },
  }]
  const fixture = context('public', {
    nerChunks: nerChunksByText([['张三', [{ type: 'person', value: '张三', confidence: 0.99 }]]]),
  })
  const currentAgent = agent(history, seedEvents)

  const result = await routeTurn(fixture, currentAgent, [current], history, {}, 2)

  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(fixture.originalCalls(), 1)
  assert.equal(currentAgent.events[1].data.classification, 'unknown')
  assert.equal(currentAgent.events[1].data.method, 'cloud-history-ner')
  assert.equal(currentAgent.events[1].data.reason, 'history-person-name')
  assert.doesNotMatch(JSON.stringify(currentAgent.events), /张三/)
})

test('the full payload scan stays clean when rebuilt history is public', async () => {
  const historyUser = userMessage('HTTP/3 uses QUIC.', 'clean-history')
  const current = userMessage('Compare that with HTTP/2.', 'clean-current')
  const history = [historyUser, current]
  const seedEvents = [{
    type: 'privacy-router/check-result',
    data: {
      turn: 1,
      decision: 'cloud',
      approvedMessageIds: [historyUser.id],
      authorization: { ok: true, scope: 'none', types: [] },
    },
  }]
  const fixture = context('public', { nerChunks: nerChunksByText([]) })

  const result = await routeTurn(fixture, agent(history, seedEvents), [current], history, {}, 2)

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.equal(nerRequests(fixture).length, 2)
  assert.equal(cloudRequests(fixture).length, 1)
})

test('a throwing NER request fails local instead of falling through', async () => {
  const fixture = context('public', {
    nerChunks: () => { throw new Error('ner transport failed') },
  })
  const currentAgent = agent()

  const result = await routeTurn(fixture, currentAgent, [userMessage('Compare HTTP/2 and HTTP/3.')])

  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(classifierRequests(fixture).length, 0)
  assert.equal(currentAgent.events[1].data.classification, 'unknown')
  assert.equal(currentAgent.events[1].data.method, 'entity-analysis')
  assert.equal(currentAgent.events[1].data.reason, 'ner-error')
  assert.deepEqual(currentAgent.events[1].data.entities, [])
  assert.equal(currentAgent.events[1].data.classifier, undefined)
})

test('check-result events omit classifier output once entities were found', async () => {
  const echoed = '用户提供了 13800000000，属于公开信息。'
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    classifierChunks: () => classifierChunks('public', echoed),
    userQuestions: { ask: async () => authorizationAnswer('允许，仅本次具体值') },
  })
  const currentAgent = agent()

  await routeTurn(fixture, currentAgent, [userMessage('联系 13800000000', 'scrubbed-phone')])

  const checkResult = currentAgent.events[1].data
  assert.equal(checkResult.classifier.finish, 'tool-calls')
  assert.equal(checkResult.classifier.output, undefined)
  assert.equal(checkResult.classifier.reason, undefined)
  assert.doesNotMatch(JSON.stringify(currentAgent.events), /13800000000/)
  assert.deepEqual(checkResult.eligibleEntities, [{ type: 'phone', count: 1 }])
  assert.equal(cloudRequests(fixture).length, 1)
})

test('check-result events keep classifier output when no entity was found', async () => {
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const currentAgent = agent()

  await routeTurn(fixture, currentAgent, [userMessage('Compare HTTP/2 and HTTP/3.')])

  const checkResult = currentAgent.events[1].data
  assert.equal(checkResult.classifier.finish, 'tool-calls')
  assert.match(checkResult.classifier.output, /tool-call structured_output/)
  assert.equal(checkResult.entities, undefined)
})

test('a queued cloud dispatch cannot be replayed by a different turn', async () => {
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const current = userMessage('Compare HTTP/2 and HTTP/3.', 'stale-current')
  const currentAgent = agent()

  const result = await routeTurn(
    fixture,
    currentAgent,
    [current],
    [current],
    { turn: 99, step: 99 },
  )

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(fixture.originalCalls(), 0)
  assert.equal(result.chunks.at(-1).reason.failure.code, 'PRIVACY_ROUTER_STALE_DISPATCH')
  assert.deepEqual(currentAgent.events.at(-1), {
    type: 'privacy-router/cloud-blocked',
    data: {
      checkId: currentAgent.events[0].data.checkId,
      turn: 1,
      step: 1,
      reason: 'stale-dispatch',
    },
  })
})

test('a queued cloud dispatch requires the approved message in the streamed payload', async () => {
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const approved = userMessage('Compare HTTP/2 and HTTP/3.', 'approved-current')
  const unrelated = userMessage('Something else entirely.', 'unrelated-current')
  const currentAgent = agent()

  const result = await routeTurn(fixture, currentAgent, [approved], [unrelated])

  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(fixture.originalCalls(), 0)
  assert.equal(result.chunks.at(-1).reason.failure.code, 'PRIVACY_ROUTER_STALE_DISPATCH')
})

test('a once-value grant never leaves a reusable sanitized copy behind', async () => {
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => {
      asks += 1
      return authorizationAnswer('允许，仅本次具体值')
    } },
  })
  const phoneUser = userMessage('联系 13800000000', 'once-cached-phone')
  const history = [phoneUser]
  const currentAgent = agent(history)

  await routeTurn(fixture, currentAgent, [phoneUser], history, {}, 1)
  assert.equal(asks, 1)
  assert.match(cloudRequests(fixture)[0].messages[0].content[0].text, /\[PHONE_REDACTED_1\]/)

  // A later session-category grant naming the same message must still not resurrect the
  // copy that was only ever authorized for one specific value in one specific turn.
  currentAgent.session.append('privacy-router/check-result', {
    turn: 2,
    decision: 'cloud',
    approvedMessageIds: [phoneUser.id],
    placeholderCount: 1,
    eligibleEntities: [{ type: 'phone', count: 1 }],
    authorization: {
      ok: true,
      scope: 'session-category',
      types: ['phone'],
      authorizedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    },
  })

  const next = userMessage('请继续解释公开概念。', 'once-cached-next')
  history.push(next)
  await routeTurn(fixture, currentAgent, [next], history, {}, 3)

  const secondCloudRequest = cloudRequests(fixture).at(-1)
  assert.deepEqual(secondCloudRequest.messages, [next])
  assert.doesNotMatch(JSON.stringify(secondCloudRequest), /13800000000|PHONE_REDACTED/)
})

test('the per-session sanitized message cache is bounded', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    userQuestions: { ask: async () => authorizationAnswer('本会话记住这些实体类别') },
  })
  const history = []
  const currentAgent = agent(history)
  const limit = 128
  const total = limit + 2

  for (let index = 0; index < total; index += 1) {
    const message = userMessage('联系 13800000000', `bounded-phone-${index}`)
    history.push(message)
    await routeTurn(fixture, currentAgent, [message], history, {}, index + 1)
  }

  const next = userMessage('请继续解释公开概念。', 'bounded-next')
  history.push(next)
  await routeTurn(fixture, currentAgent, [next], history, {}, total + 1)

  const sentIds = cloudRequests(fixture).at(-1).messages.map(message => String(message.id))
  const retained = sentIds.filter(id => id.startsWith('bounded-phone-'))
  assert.equal(retained.length, limit)
  assert.equal(retained.includes('bounded-phone-0'), false)
  assert.equal(retained.includes('bounded-phone-1'), false)
  assert.equal(retained.includes('bounded-phone-2'), true)
  assert.equal(retained.includes(`bounded-phone-${total - 1}`), true)
  assert.equal(sentIds.at(-1), 'bounded-next')
  assert.doesNotMatch(JSON.stringify(cloudRequests(fixture).at(-1)), /13800000000/)
})

async function auxiliaryChunks(fixture, sessionId) {
  const chunks = []
  for await (const chunk of fixture.stream({
    provider: CLOUD_ROUTE.provider,
    model: CLOUD_ROUTE.model,
    purpose: 'session-title',
    sessionId,
    messages: [userMessage('Summarize this session.')],
  }, fixture.original)) chunks.push(chunk)
  return chunks
}

test('tracked session state is bounded and evicted sessions fail closed', async () => {
  const fixture = context('public', { nerChunks: nerChunks([]) })
  const sessionIds = []
  const total = 33

  for (let index = 0; index < total; index += 1) {
    const sessionId = `bounded-session-${index}`
    sessionIds.push(sessionId)
    const message = userMessage('Compare HTTP/2 and HTTP/3.', `${sessionId}-message`)
    await routeTurn(fixture, agent([], [], sessionId), [message])
  }

  const before = fixture.requests.length
  const evicted = await auxiliaryChunks(fixture, sessionIds[0])
  assert.equal(evicted.at(-1).reason.kind, 'error')
  assert.equal(evicted.at(-1).reason.failure.code, 'PRIVACY_ROUTER_AUXILIARY_CLOUD_BLOCKED')
  // Blocked outright, so the request never reached any provider at all.
  assert.equal(fixture.requests.length, before)

  const retained = await auxiliaryChunks(fixture, sessionIds.at(-1))
  assert.notEqual(retained.at(-1).reason.kind, 'error')
  assert.equal(fixture.requests.length, before + 1)
  const forcedRequest = fixture.requests.at(-1)
  assert.equal(forcedRequest.provider, LOCAL_ROUTE.provider)
  assert.equal(forcedRequest.model, LOCAL_ROUTE.model)
  assert.equal(forcedRequest.purpose, 'session-title')
})

const USER_CHOICE_CONFIG = {
  routingMode: 'user-choice',
  localProvider: LOCAL_ROUTE.provider,
  localModel: LOCAL_ROUTE.model,
  localFailureTimeoutMs: 30,
}

function failingNext(code = 'ECONNREFUSED', message = 'local connection refused') {
  return async () => {
    throw Object.assign(new Error(message), { code })
  }
}

function rejectingStreamNext(code = 'ECONNRESET', message = 'local first chunk failed') {
  const failure = () => Promise.reject(Object.assign(new Error(message), { code }))
  return async () => ({
    [Symbol.asyncIterator]() {
      return this
    },
    next: failure,
  })
}

async function* errorFinishStream() {
  yield {
    type: 'finish',
    reason: {
      kind: 'error',
      failure: { code: 'LOCAL_UPSTREAM_ERROR', message: 'local model process exited' },
    },
  }
}

async function* silentLocalStream() {
  await new Promise(() => {})
}

async function* partialThenThrowStream() {
  yield { type: 'block-start', index: 0, blockType: 'text' }
  yield { type: 'text-delta', index: 0, text: 'local partial answer' }
  throw new Error('connection reset mid-stream')
}

async function* trickleThenHangStream() {
  // Non-content chunks must not extend the single first-token deadline.
  yield { type: 'block-start', index: 0, blockType: 'reasoning' }
  await new Promise(resolve => setTimeout(resolve, 20))
  yield { type: 'reasoning-start', index: 0 }
  await new Promise(resolve => setTimeout(resolve, 20))
  yield { type: 'block-start', index: 1, blockType: 'text' }
  await new Promise(() => {})
}

async function consumeFailingTurn(fixture, currentAgent, message, original, turn = 1) {
  await fixture.preStep({
    agent: currentAgent,
    messages: [message],
    turn,
    step: 1,
    signal: new AbortController().signal,
  }, async () => undefined)
  const route = await fixture.request({
    agent: currentAgent,
    turn,
    step: 1,
    signal: new AbortController().signal,
  }, async () => LOCAL_ROUTE)
  const chunks = []
  let thrown
  try {
    for await (const chunk of fixture.stream({
      ...route,
      messages: [message],
      system: 'public system note',
      tools: [],
      sessionId: currentAgent.session.id,
    }, original)) chunks.push(chunk)
  } catch (error) {
    thrown = error
  }
  return { route, chunks, thrown }
}

test('user-choice config requires a trusted local landing', () => {
  assert.throws(
    () => resolveConfig({ routingMode: 'user-choice' }),
    /requires localProvider and localModel/,
  )
  assert.throws(
    () => resolveConfig({
      routingMode: 'user-choice',
      localProvider: 'untrusted-cloud',
      localModel: 'some-model',
    }),
    /match trustedProviders/,
  )
  assert.doesNotThrow(() => resolveConfig(USER_CHOICE_CONFIG))
  assert.doesNotThrow(() => resolveConfig())
})

test('user-choice honors a selected cloud model for public turns', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Compare HTTP/2 and HTTP/3.', 'choice-public')
  const result = await routeTurn(fixture, cloudAgent(), [current], [current], {
    nextRoute: CLOUD_ROUTE,
  })

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  assert.equal(cloudRequests(fixture).length, 1)
  const checkResult = fixture.requests.length && result
  assert.equal(checkResult.route.provider, CLOUD_ROUTE.provider)
})

test('user-choice forces a cloud-selected sensitive turn back to local', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('检查 /Users/example/secret/config.ts 的内容', 'choice-sensitive')
  const currentAgent = cloudAgent()
  const result = await routeTurn(fixture, currentAgent, [current], [current], {
    nextRoute: CLOUD_ROUTE,
  })

  assert.deepEqual(result.route, LOCAL_ROUTE)
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(result.chunks.some(chunk => chunk.text === 'local answer'), true)
  const event = currentAgent.events[1].data
  assert.equal(event.userPreference, 'cloud')
  assert.equal(event.decision, 'local')
  assert.equal(event.reason, 'local-path')
})

test('user-choice never falls back to cloud when a cloud-selected sensitive turn fails locally', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('检查 /Users/example/secret/config.ts 的内容', 'choice-sensitive-fail')
  const currentAgent = cloudAgent()
  const { thrown } = await consumeFailingTurn(
    fixture,
    currentAgent,
    current,
    rejectingStreamNext(),
  )

  assert.equal(thrown instanceof Error, true)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('local preference falls back to cloud on a local transport error for a public turn', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Compare HTTP/2 and HTTP/3.', 'fallback-transport')
  const currentAgent = agent()
  const result = await routeTurn(fixture, currentAgent, [current], [current], {
    original: failingNext(),
  })

  assert.deepEqual(result.route, LOCAL_ROUTE)
  const cloudRequest = cloudRequests(fixture)[0]
  assert.equal(cloudRequest !== undefined, true)
  assert.deepEqual(cloudRequest.messages.map(message => message.id), [current.id])
  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
  const fallbackEvent = currentAgent.events.find(
    event => event.type === 'privacy-router/local-fallback',
  )
  assert.equal(fallbackEvent.data.reason, 'ECONNREFUSED')
  assert.equal(fallbackEvent.data.fallback, 'cloud')
  const decisionEvent = currentAgent.events[1].data
  assert.equal(decisionEvent.userPreference, 'local')
  assert.equal(decisionEvent.localFailureCloudFallback, 'ready')
})

test('local preference falls back to cloud on an error finish before any content', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain QUIC handshake.', 'fallback-error-finish')
  const result = await routeTurn(fixture, agent(), [current], [current], {
    original: errorFinishStream,
  })

  assert.equal(cloudRequests(fixture).length, 1)
  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
  const fallbackEvent = result.chunks
  assert.equal(fallbackEvent.length > 0, true)
})

test('local preference falls back to cloud on a first-token timeout', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain TLS 1.3.', 'fallback-timeout')
  const result = await routeTurn(fixture, agent(), [current], [current], {
    original: silentLocalStream,
  })

  assert.equal(cloudRequests(fixture).length, 1)
  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
})

test('local preference does not switch to cloud after local content has started', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain WebRTC.', 'fallback-midstream')
  const { chunks, thrown } = await consumeFailingTurn(
    fixture,
    agent(),
    current,
    partialThenThrowStream,
  )

  assert.equal(thrown instanceof Error, true)
  assert.equal(chunks.some(chunk => chunk.text === 'local partial answer'), true)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('local preference keeps a hard-blocked turn local even when local generation fails', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('读取 /Users/example/secret/key.pem', 'fallback-hard-block')
  const { chunks, thrown } = await consumeFailingTurn(
    fixture,
    agent(),
    current,
    rejectingStreamNext(),
  )

  assert.equal(thrown instanceof Error, true)
  assert.equal(chunks.length, 0)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('local failure with a phone asks for placeholder authorization at failure time', async () => {
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
    userQuestions: {
      ask: async () => {
        asks += 1
        return authorizationAnswer('拒绝，留在本地')
      },
    },
  })
  const current = userMessage('联系 13800000000', 'fallback-phone-deny')
  const { chunks } = await consumeFailingTurn(fixture, agent(), current, failingNext())

  assert.equal(asks, 1)
  assert.equal(cloudRequests(fixture).length, 0)
  assert.equal(chunks.at(-1).reason.kind, 'error')
  assert.equal(
    chunks.at(-1).reason.failure.code,
    'PRIVACY_ROUTER_FALLBACK_AUTHORIZATION_DENIED',
  )
})

test('local failure with a phone can placehold and use the cloud after a one-time grant', async () => {
  let asks = 0
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
    userQuestions: {
      ask: async () => {
        asks += 1
        return authorizationAnswer('允许，仅本次具体值')
      },
    },
  })
  const current = userMessage('联系 13800000000', 'fallback-phone-allow')
  const currentAgent = agent()
  const result = await routeTurn(fixture, currentAgent, [current], [current], {
    original: failingNext(),
  })

  assert.equal(asks, 1)
  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
  const cloudRequest = cloudRequests(fixture)[0]
  assert.match(cloudRequest.messages[0].content[0].text, /\[PHONE_REDACTED_1\]/)
  assert.doesNotMatch(JSON.stringify(cloudRequest), /13800000000/)
  const fallbackGrants = currentAgent.events.filter(
    event => event.type === 'privacy-router/check-result' && event.data.decision === 'cloud',
  )
  assert.equal(fallbackGrants.length, 1)
  assert.equal(fallbackGrants[0].data.method, 'local-failure-fallback')
})

test('local failure with a phone can placehold after a session-category grant', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
    userQuestions: {
      ask: async () => authorizationAnswer('本会话记住这些实体类别'),
    },
  })
  const current = userMessage('联系 13800000000', 'fallback-phone-session')
  const currentAgent = agent()
  const result = await routeTurn(fixture, currentAgent, [current], [current], {
    original: failingNext(),
  })

  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
  const cloudRequest = cloudRequests(fixture)[0]
  assert.match(cloudRequest.messages[0].content[0].text, /\[PHONE_REDACTED_1\]/)
  assert.doesNotMatch(JSON.stringify(cloudRequest), /13800000000/)
  const fallbackDecision = currentAgent.events.find(
    event => event.type === 'privacy-router/check-result'
      && event.data.method === 'local-failure-fallback',
  )
  assert.equal(fallbackDecision.data.authorization.scope, 'session-category')
})

test('a dormant fallback voucher cannot be consumed by a cloud request before local fails', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Compare TCP and QUIC.', 'dormant-anchor')
  const currentAgent = agent()
  await fixture.preStep({
    agent: currentAgent,
    messages: [current],
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
  assert.deepEqual(route, LOCAL_ROUTE)

  // An unsolicited cloud stream (e.g. another component ignoring local selection) must
  // not be able to spend the voucher while the local leg is still pending.
  const chunks = []
  for await (const chunk of fixture.stream({
    provider: CLOUD_ROUTE.provider,
    model: CLOUD_ROUTE.model,
    messages: [current],
    system: 'x',
    tools: [],
    sessionId: currentAgent.session.id,
  }, fixture.original)) chunks.push(chunk)

  assert.equal(chunks.at(-1).reason.kind, 'error')
  assert.equal(
    chunks.at(-1).reason.failure.code,
    'PRIVACY_ROUTER_DORMANT_FALLBACK_REJECTED',
  )
  assert.equal(cloudRequests(fixture).length, 0)
})

test('the first-token deadline is a single deadline even when non-content chunks trickle in', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: { ...USER_CHOICE_CONFIG, localFailureTimeoutMs: 60 },
  })
  const current = userMessage('Explain gRPC.', 'trickle-anchor')
  const startedAt = Date.now()
  const result = await routeTurn(fixture, agent(), [current], [current], {
    original: trickleThenHangStream,
  })
  const elapsed = Date.now() - startedAt

  assert.equal(cloudRequests(fixture).length, 1)
  assert.equal(result.chunks.some(chunk => chunk.text === 'cloud answer'), true)
  // Three 20ms-spaced non-content chunks would push a per-next resetting timer past
  // 100ms; the single deadline must fire near 60ms.
  assert.equal(elapsed < 300, true, `fallback took ${elapsed}ms`)
})

test('a user-aborted local request does not trigger the cloud fallback', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain MPTCP.', 'aborted-anchor')
  const currentAgent = agent()
  await fixture.preStep({
    agent: currentAgent,
    messages: [current],
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
  const aborted = new AbortController()
  aborted.abort()
  const chunks = []
  for await (const chunk of fixture.stream({
    ...route,
    messages: [current],
    system: 'x',
    tools: [],
    sessionId: currentAgent.session.id,
    signal: aborted.signal,
  }, failingNext())) chunks.push(chunk)

  assert.equal(chunks.length, 0)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('user-choice runs NER and classification on the configured landing, not the selected provider', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: {
      ...USER_CHOICE_CONFIG,
      localProvider: 'local-ai-configured',
      localModel: 'configured-local-model',
    },
  })
  const current = userMessage('Compare SCTP and QUIC.', 'configured-landing')
  const result = await routeTurn(fixture, cloudAgent(), [current], [current], {
    nextRoute: CLOUD_ROUTE,
  })

  assert.deepEqual(result.route, { ...CLOUD_ROUTE, maxTokens: 8_192 })
  const safetyRequests = fixture.requests.filter(
    request => request.tools?.[0]?.name === 'structured_output'
      || request.tools?.[0]?.name === 'structured_ner_output',
  )
  assert.equal(safetyRequests.length, 2)
  for (const request of safetyRequests) {
    assert.equal(request.provider, 'local-ai-configured')
    assert.equal(request.model, 'configured-local-model')
  }
})

test('a stale fallback voucher for a different message runs local without activating the cloud', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const approved = userMessage('Approved question.', 'stale-voucher-approved')
  const currentAgent = agent()
  await fixture.preStep({
    agent: currentAgent,
    messages: [approved],
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

  const { chunks, thrown } = await consumeFailingTurn(
    fixture,
    currentAgent,
    userMessage('A different message entirely.', 'stale-voucher-other'),
    rejectingStreamNext(),
    1,
  )

  assert.equal(chunks.length, 0)
  assert.equal(thrown instanceof Error, true)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('a voucher consumed by local content cannot be resurrected by a same-turn replay', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain UDP.', 'content-started-anchor')
  const currentAgent = agent()

  // First stream starts delivering local content, which consumes the dormant voucher.
  const first = await routeTurn(fixture, currentAgent, [current], [current], {
    original: async function* () {
      yield { type: 'block-start', index: 0, blockType: 'text' }
      yield { type: 'text-delta', index: 0, text: 'local answer body' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    },
  })
  assert.equal(first.chunks.some(chunk => chunk.text === 'local answer body'), true)

  // A provider-level retry re-enters agent/request for the same turn. The local stream
  // now fails; the already-consumed voucher must not activate the cloud.
  const { chunks, thrown } = await consumeFailingTurn(
    fixture,
    currentAgent,
    current,
    rejectingStreamNext('ECONNRESET'),
    1,
  )

  assert.equal(thrown instanceof Error, true)
  assert.equal(chunks.length, 0)
  assert.equal(cloudRequests(fixture).length, 0)
})

test('concurrent failing local streams can only activate the cloud fallback once', async () => {
  const fixture = context('public', {
    nerChunks: nerChunks([]),
    config: USER_CHOICE_CONFIG,
  })
  const current = userMessage('Explain IPsec.', 'concurrent-anchor')
  const currentAgent = agent()
  await fixture.preStep({
    agent: currentAgent,
    messages: [current],
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

  // Two local streams fail at the same time; only one may claim the single-use voucher.
  const streamOptions = {
    ...route,
    messages: [current],
    system: 'x',
    tools: [],
    sessionId: currentAgent.session.id,
  }
  const collect = async () => {
    const chunks = []
    for await (const chunk of fixture.stream(streamOptions, failingNext())) chunks.push(chunk)
    return chunks
  }
  const [first, second] = await Promise.all([collect(), collect()])

  const cloudBodies = [...first, ...second].filter(chunk => chunk.text === 'cloud answer')
  assert.equal(cloudBodies.length, 1)
  assert.equal(cloudRequests(fixture).length, 1)
})
