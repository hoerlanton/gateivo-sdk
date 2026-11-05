if (Number(process.versions.node.split('.')[0]) !== 24) {
  console.error('The authenticated HTTP login example requires Node.js 24.');
  process.exitCode = 1;
} else {
  console.log('Authenticated HTTP backend example · local fictional fixture');
  console.log('Real password/session, SDK consent, signed JWT verification, SQLite, MCP and HTTP.');
  console.log('Synthetic provider transport and loopback TLS-proxy simulation; no hosted WorkOS, Claude or Laravel validation.\n');
  try {
    const { runLoginHttpBackendExercise } = await import('./login-exercise.mjs');
    const { checks } = await runLoginHttpBackendExercise();
    for (const check of checks) console.log(`- ${check}`);
    console.log('\nTemporary servers and private database removed.');
  } catch (error) {
    console.error(error?.name === 'LoginExerciseError' ? error.message : 'Authenticated HTTP example could not complete.');
    process.exitCode = 1;
  }
}
