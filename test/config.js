/*!
 * Copyright (c) 2024 Instun, Inc. All rights reserved.
 */

// 检测运行环境
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;
const isBrowser = !isNode && typeof window !== 'undefined';

let implementation;

// 根据环境和配置动态导入实现
if (isNode && !process.env.FORCE_BROWSER_IMPL) {
  // Node.js 环境使用原生加密实现
  implementation = await import('../lib/index.js');
} else {
  // 浏览器环境或强制使用浏览器实现
  implementation = await import('../lib/browser.js');
}

export const {
  SM2Multikey,
  cryptosuite
} = implementation;
