/**
 * @name Clear text storage of sensitive information (+ session credentials)
 * @description Sensitive information stored without encryption or hashing can expose it to an
 *              attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id sast-bench/clear-text-storage-ext
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-315
 *       external/cwe/cwe-359
 */

import javascript
import TokenHeuristics
import semmle.javascript.security.dataflow.CleartextStorageQuery
import ClearTextStorageFlow::PathGraph

from ClearTextStorageFlow::PathNode source, ClearTextStorageFlow::PathNode sink
where ClearTextStorageFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This stores sensitive data returned by $@ as clear text.",
  source.getNode(), source.getNode().(Source).describe()
