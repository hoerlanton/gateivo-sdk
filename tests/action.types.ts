// Checked by npm run typecheck; these cases are intentionally not executed.
import { z } from 'zod/v4';
import { defineAction, type ActionContext, type AppAction } from '../src/sdk.js';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends
  (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;

const metadata = {
  name: 'list_items', title: 'List items', description: 'List owned items', requiredScopes: ['items:read'],
};
const inputSchema = z.object({
  limit: z.number().default(10),
  query: z.string().optional(),
  numericId: z.string().transform(Number),
});
const outputSchema = z.object({ total: z.number(), owner: z.string() });

const list = defineAction({
  ...metadata, inputSchema, outputSchema,
  execute: async (input, context) => {
    type InputIsParsed = Assert<Equal<typeof input, { limit: number; query?: string; numericId: number }>>;
    type ContextIsTyped = Assert<Equal<typeof context, ActionContext>>;
    // @ts-expect-error Defaults are applied before execution, so limit is a number.
    const limit: string = input.limit;
    // @ts-expect-error The handler cannot access arguments absent from its schema.
    input.userId;
    return { total: input.limit + input.numericId, owner: context.principal.subject };
  },
});

type ResultMatchesSchema = Assert<Equal<Awaited<ReturnType<typeof list.execute>>, z.output<typeof outputSchema>>>;
type SchemaTypeIsRetained = Assert<Equal<typeof list.inputSchema, typeof inputSchema>>;

defineAction({
  ...metadata, inputSchema, outputSchema,
  // @ts-expect-error A wrong field type must not widen the schema-derived output.
  execute: async () => ({ total: '10', owner: 'alice' }),
});

defineAction({
  ...metadata, inputSchema, outputSchema,
  // @ts-expect-error Required output fields cannot be omitted.
  execute: async () => ({ total: 10 }),
});

defineAction({
  ...metadata, inputSchema, outputSchema,
  // @ts-expect-error An explicit handler annotation cannot override the input schema.
  execute: async (_input: { limit: string }) => ({ total: 10, owner: 'alice' }),
});

defineAction({
  ...metadata, inputSchema,
  // @ts-expect-error Actions must return objects, not primitive output schemas.
  outputSchema: z.string(),
  execute: async () => ({ total: 10 }),
});

const detail = defineAction({
  ...metadata, name: 'get_item',
  inputSchema: z.object({ id: z.string() }),
  outputSchema: z.object({ label: z.string() }),
  execute: async ({ id }) => ({ label: id }),
});

// Existing explicitly typed actions and heterogeneous registry arrays remain valid.
const compatible: AppAction<z.output<typeof inputSchema>, z.output<typeof outputSchema>> = list;
const actions: AppAction[] = [compatible, detail];
void actions;
