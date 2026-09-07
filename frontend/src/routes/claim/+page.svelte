<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	let name = $state('');
	let email = $state('');
	let password = $state('');
	let timezone = $state(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
	let submitting = $state(false);
	let error = $state('');

	onMount(async () => {
		const res = await fetch('/v1/auth/status');
		if (res.ok) {
			const status = await res.json();
			if (status.claimed) {
				window.location.href = '/admin/login';
			}
		}
	});

	async function claim(e: SubmitEvent) {
		e.preventDefault();
		submitting = true;
		error = '';
		try {
			const res = await fetch('/v1/auth/claim', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: name.trim(), email: email.trim().toLowerCase(), password, timezone })
			});
			const data = await res.json().catch(() => ({}));
			if (res.ok) {
				window.location.href = '/admin';
			} else if (res.status === 409) {
				window.location.href = '/admin/login';
			} else {
				error = data.error || 'Setup failed. Please try again.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head><title>Set up Bonnie</title></svelte:head>

<div class="flex min-h-screen items-center justify-center bg-muted/30 p-6">
	<div class="w-full max-w-sm">
		<div class="mb-8 text-center">
			<div class="mb-3 flex justify-center">
				<img src="/favicon.svg" alt="Bonnie" width="36" height="36" />
			</div>
			<h1 class="text-xl font-semibold tracking-tight">Welcome to Bonnie</h1>
			<p class="mt-1 text-sm text-muted-foreground">You're the first here — create your owner account.</p>
		</div>

		{#if error}
			<div class="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>
		{/if}

		<form onsubmit={claim} class="space-y-4">
			<div class="space-y-1.5">
				<Label for="name">Full name</Label>
				<Input id="name" type="text" autocomplete="name" bind:value={name} required />
			</div>
			<div class="space-y-1.5">
				<Label for="email">Email</Label>
				<Input id="email" type="email" autocomplete="email" bind:value={email} required />
			</div>
			<div class="space-y-1.5">
				<Label for="password">Password</Label>
				<Input id="password" type="password" autocomplete="new-password" bind:value={password} required minlength={8} />
				<p class="text-xs text-muted-foreground">Minimum 8 characters</p>
			</div>
			<Button type="submit" class="h-11 w-full" disabled={submitting}>
				{submitting ? 'Creating account…' : 'Create owner account'}
			</Button>
		</form>
	</div>
</div>
