<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	let token = $derived($page.params.token);
	let inviteEmail = $state('');
	let valid = $state<boolean | null>(null);

	let name = $state('');
	let password = $state('');
	let timezone = $state(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
	let submitting = $state(false);
	let error = $state('');

	onMount(async () => {
		const res = await fetch(`/v1/invites/${token}`);
		if (res.ok) {
			const data = await res.json();
			inviteEmail = data.email;
			valid = true;
		} else {
			valid = false;
		}
	});

	async function claim(e: SubmitEvent) {
		e.preventDefault();
		submitting = true;
		error = '';
		try {
			const res = await fetch(`/v1/invites/${token}/claim`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: name.trim(), password, timezone })
			});
			const data = await res.json().catch(() => ({}));
			if (res.ok) {
				window.location.href = '/admin';
			} else {
				error = data.error || 'Could not complete setup. Please try again.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head><title>Accept invite — Bonnie</title></svelte:head>

<div class="flex min-h-screen items-center justify-center bg-muted/30 p-6">
	<div class="w-full max-w-sm">
		<div class="mb-8 text-center">
			<div class="mb-3 flex justify-center">
				<img src="/favicon.svg" alt="Bonnie" width="36" height="36" />
			</div>
			<h1 class="text-xl font-semibold tracking-tight">You've been invited</h1>
		</div>

		{#if valid === null}
			<p class="text-center text-sm text-muted-foreground">Checking your invite…</p>
		{:else if valid === false}
			<div class="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive text-center">
				This invite link has expired or already been used. Ask your admin to send a new one.
			</div>
		{:else}
			<div class="mb-5 rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground">
				This invite is for <span class="font-medium text-foreground">{inviteEmail}</span>.
				It cannot be used by anyone else.
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
					<Label for="email-display">Email</Label>
					<Input id="email-display" type="email" value={inviteEmail} disabled />
				</div>
				<div class="space-y-1.5">
					<Label for="password">Password</Label>
					<Input id="password" type="password" autocomplete="new-password" bind:value={password} required minlength={8} />
					<p class="text-xs text-muted-foreground">Minimum 8 characters</p>
				</div>
				<Button type="submit" class="h-11 w-full" disabled={submitting}>
					{submitting ? 'Creating account…' : 'Create account'}
				</Button>
			</form>
		{/if}
	</div>
</div>
