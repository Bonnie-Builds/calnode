<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	type AuthStatus = {
		claimed: boolean;
		email_login: boolean;
		providers: string[];
		smtp_configured: boolean;
		demo_mode: boolean;
	};

	let status = $state<AuthStatus | null>(null);
	let email = $state('');
	let password = $state('');
	let submitting = $state(false);
	let loginError = $state('');
	let magicSubmitting = $state(false);
	let magicMessage = $state('');
	let magicError = $state('');
	let magicEmail = $state('');

	const oauthErrorMessages: Record<string, string> = {
		state: 'Login failed: invalid session state. Please try again.',
		denied: 'You denied access. Sign in is required to use the admin.',
		oauth: 'OAuth error. Please try again.',
		userinfo: 'Could not fetch your profile. Please try again.',
		no_account: 'No Bonnie account found for your email. Contact your admin.',
		archived: 'Your account has been archived. If you think this is an error, please contact your workspace admin.',
		session: 'Could not create a session. Please try again.',
		link: 'This login link is invalid or has expired. Request a new one below.'
	};

	const errorKey = $derived($page.url.searchParams.get('error') ?? '');
	const oauthError = $derived(errorKey ? (oauthErrorMessages[errorKey] ?? 'An error occurred. Please try again.') : '');

	onMount(async () => {
		const res = await fetch('/v1/auth/status');
		if (res.ok) {
			status = await res.json();
			if (!status?.claimed) {
				window.location.href = '/admin/claim';
				return;
			}
			if (status?.demo_mode) {
				window.location.href = '/v1/demo/enter';
			}
		}
	});

	async function loginEmail(e: SubmitEvent) {
		e.preventDefault();
		submitting = true;
		loginError = '';
		try {
			const res = await fetch('/v1/auth/login/email', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email: email.trim().toLowerCase(), password })
			});
			if (res.ok) {
				window.location.href = '/admin';
			} else {
				const data = await res.json().catch(() => ({}));
				loginError = data.error || 'Login failed. Please try again.';
			}
		} finally {
			submitting = false;
		}
	}

	const isValidEmail = (e: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

	async function sendMagicLink() {
		const addr = magicEmail.trim().toLowerCase();
		// Require a valid address up front — otherwise the request silently no-ops (the
		// endpoint returns the same generic message), which looks like nothing happened.
		if (!isValidEmail(addr)) {
			magicError = 'Enter a valid email address first.';
			return;
		}
		magicError = '';
		magicSubmitting = true;
		loginError = '';
		try {
			const res = await fetch('/v1/auth/magic-link/request', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email: addr })
			});
			const data = await res.json().catch(() => ({}));
			magicMessage = data.message || 'If an account with that email exists, a login link is on its way.';
		} catch {
			magicMessage = 'If an account with that email exists, a login link is on its way.';
		} finally {
			magicSubmitting = false;
		}
	}

	const showGoogle = $derived(status?.providers?.includes('google') ?? false);
	const showMicrosoft = $derived(status?.providers?.includes('microsoft') ?? false);
	const showEmail = $derived(status?.email_login ?? false);
	const showForgot = $derived(status?.smtp_configured ?? false);
	const showMagic = $derived(status?.smtp_configured ?? false);
	const showDivider = $derived((showGoogle || showMicrosoft) && showEmail);
</script>

<svelte:head><title>Sign in — Bonnie</title></svelte:head>

<div class="flex min-h-screen items-center justify-center bg-muted/30 p-6">
	<div class="w-full max-w-sm">
		<div class="mb-8 text-center">
			<div class="mb-3 flex justify-center">
				<img src="/favicon.svg" alt="Bonnie" width="36" height="36" />
			</div>
			<h1 class="text-xl font-semibold tracking-tight">Sign in to Bonnie</h1>
		</div>

		{#if oauthError}
			<div class="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{oauthError}</div>
		{/if}
		{#if loginError}
			<div class="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{loginError}</div>
		{/if}

		{#if status === null || status.demo_mode}
			<div class="text-center text-sm text-muted-foreground">
				{status?.demo_mode ? 'Entering demo…' : 'Loading…'}
			</div>
		{:else}
			{#if showGoogle}
				<Button variant="outline" class="h-11 w-full" onclick={() => window.location.href = '/v1/auth/login'}>
					<svg width="16" height="16" viewBox="0 0 48 48" aria-hidden="true" class="mr-2">
						<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
						<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
						<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
						<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.29-8.16 2.29-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
					</svg>
					Sign in with Google
				</Button>
			{/if}

			{#if showMicrosoft}
				<Button variant="outline" class="h-11 w-full {showGoogle ? 'mt-3' : ''}" onclick={() => window.location.href = '/v1/auth/microsoft/login'}>
					<svg width="16" height="16" viewBox="0 0 23 23" aria-hidden="true" class="mr-2">
						<path fill="#F25022" d="M1 1h10v10H1z"/>
						<path fill="#7FBA00" d="M12 1h10v10H12z"/>
						<path fill="#00A4EF" d="M1 12h10v10H1z"/>
						<path fill="#FFB900" d="M12 12h10v10H12z"/>
					</svg>
					Sign in with Microsoft
				</Button>
			{/if}

			{#if showDivider}
				<div class="my-4 flex items-center gap-3 text-xs text-muted-foreground">
					<div class="h-px flex-1 bg-border"></div>
					or
					<div class="h-px flex-1 bg-border"></div>
				</div>
			{/if}

			{#if showEmail}
				<form onsubmit={loginEmail} class="space-y-4">
					<div class="space-y-1.5">
						<Label for="email">Email</Label>
						<Input id="email" type="email" autocomplete="email" bind:value={email} required />
					</div>
					<div class="space-y-1.5">
						<div class="flex items-center justify-between">
							<Label for="password">Password</Label>
							{#if showForgot}
								<a href="/admin/forgot-password" class="text-xs text-muted-foreground hover:underline">Forgot password?</a>
							{/if}
						</div>
						<Input id="password" type="password" autocomplete="current-password" bind:value={password} required />
					</div>
					<Button type="submit" class="h-11 w-full" disabled={submitting}>
						{submitting ? 'Signing in…' : 'Sign in'}
					</Button>
				</form>
			{/if}

			{#if showMagic}
				{#if showGoogle || showMicrosoft || showEmail}
					<div class="my-4 flex items-center gap-3 text-xs text-muted-foreground">
						<div class="h-px flex-1 bg-border"></div>
						or
						<div class="h-px flex-1 bg-border"></div>
					</div>
				{/if}
				{#if magicMessage}
					<div class="rounded-md bg-green-50 px-3 py-2.5 text-sm text-green-700">{magicMessage}</div>
				{:else}
					<form onsubmit={(e) => { e.preventDefault(); sendMagicLink(); }} class="space-y-3">
						<div class="space-y-1.5">
							<Label for="magic-email">Email</Label>
							<Input id="magic-email" type="email" autocomplete="email" placeholder="you@example.com"
								bind:value={magicEmail} oninput={() => (magicError = '')} aria-invalid={magicError ? 'true' : undefined} />
							{#if magicError}
								<p class="text-xs text-destructive">{magicError}</p>
							{/if}
						</div>
						<Button type="submit" variant="outline" class="h-11 w-full" disabled={magicSubmitting}>
							{magicSubmitting ? 'Sending…' : 'Email me a login link'}
						</Button>
						<p class="text-center text-xs text-muted-foreground">A one-time sign-in link, no password needed.</p>
					</form>
				{/if}
			{/if}

			{#if !showGoogle && !showMicrosoft && !showEmail && !showMagic}
				<p class="text-center text-sm text-muted-foreground">No login methods are configured. Contact your administrator.</p>
			{/if}
		{/if}
	</div>
</div>
