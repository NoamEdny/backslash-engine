import { QueryError } from './model.js';
import type { GraphNode, GraphEdge } from '../graph/model.js';
import type { Filter, Scope } from './model.js';
export interface FilterDefinition {
  readonly id: string;
  readonly description: string;
  readonly filter: Filter;
}
/** Trusted server-side callbacks are never accepted from query JSON. */
export interface CustomFilterDefinition {
  readonly id: string;
  readonly description: string;
  readonly scope: Scope;
  readonly match: (entity: GraphNode | GraphEdge) => boolean;
}
export type ResolvedFilter = Filter | Pick<CustomFilterDefinition, 'scope' | 'match'>;
export type FilterMetadata = FilterDefinition | Omit<CustomFilterDefinition, 'match'>;

export class FilterRegistry {
  private readonly definitions = new Map<string, FilterDefinition | CustomFilterDefinition>();

  private validateId(id: string): void {
    if (typeof id !== 'string' || !id.trim() || this.definitions.has(id)) {
      throw new QueryError('registry', 'Invalid or duplicate filter ID');
    }
  }

  register(definition: FilterDefinition): this {
    this.validateId(definition.id);
    // Copy definitions so callers cannot mutate registered predicates afterwards.
    this.definitions.set(definition.id, structuredClone(definition));
    return this;
  }

  registerCustom(definition: CustomFilterDefinition): this {
    const { id, description, scope, match } = definition;
    this.validateId(id);
    if (
      typeof description !== 'string' ||
      !['START', 'END', 'ANY_NODE', 'ALL_NODES', 'ALL_EDGES'].includes(scope) ||
      typeof match !== 'function'
    ) {
      throw new QueryError('registry', 'Invalid custom filter');
    }
    this.definitions.set(id, { id, description, scope, match });
    return this;
  }

  resolve(id: string): ResolvedFilter | undefined {
    const definition = this.definitions.get(id);
    if (!definition) return undefined;
    if ('match' in definition) {
      return { scope: definition.scope, match: definition.match };
    }
    return structuredClone(definition.filter);
  }

  list(): FilterMetadata[] {
    // Expose only serializable metadata, never executable callback code.
    return Array.from(this.definitions.values(), (definition) => {
      if ('match' in definition) {
        const { id, description, scope } = definition;
        return { id, description, scope };
      }
      return structuredClone(definition);
    });
  }
}
export function createDefaultRegistry(): FilterRegistry {
  return new FilterRegistry()
    .register({
      id: 'public',
      description: 'Starts at a public node',
      filter: { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    })
    .register({
      id: 'sink',
      description: 'Ends at an RDS or SQL node',
      filter: { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds', 'sql'] } },
    })
    .register({
      id: 'vulnerability',
      description: 'Contains a vulnerable node',
      filter: { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
    });
}
