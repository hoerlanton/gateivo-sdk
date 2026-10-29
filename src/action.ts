import type { z } from 'zod/v4';
import type { ActionContext, AppAction } from './types.js';

type ActionDefinition<
  InputSchema extends z.ZodType,
  OutputSchema extends z.ZodType<Record<string, unknown>>,
> = Omit<AppAction, 'inputSchema' | 'outputSchema' | 'execute'> & {
  inputSchema: InputSchema;
  outputSchema: OutputSchema;
  execute: (
    input: z.output<NoInfer<InputSchema>>, context: ActionContext,
  ) => Promise<z.output<NoInfer<OutputSchema>>>;
};

/**
 * Infer an action's handler types from its schemas, including input defaults.
 * This returns the action unchanged; the registry still validates each call.
 */
export function defineAction<
  InputSchema extends z.ZodType,
  OutputSchema extends z.ZodType<Record<string, unknown>>,
>(action: ActionDefinition<InputSchema, OutputSchema>): ActionDefinition<InputSchema, OutputSchema> {
  return action;
}
