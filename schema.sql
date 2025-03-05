-- Create users table
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create items table if it doesn't exist yet
CREATE TABLE IF NOT EXISTS public.items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    text TEXT NOT NULL,
    entity TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    position INTEGER NOT NULL,
    category TEXT NOT NULL,
    user_id UUID REFERENCES public.users(id),
    resource_id UUID REFERENCES public.resources(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create resources table
CREATE TABLE IF NOT EXISTS public.resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id UUID REFERENCES public.users(id)
);

-- Enable Row Level Security
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.resources ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Users can view all users" ON public.users
    FOR SELECT USING (true);

CREATE POLICY "Users can update their own data" ON public.users
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can view all items" ON public.items
    FOR SELECT USING (true);

CREATE POLICY "Users can insert items" ON public.items
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own items" ON public.items
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own items" ON public.items
    FOR DELETE USING (auth.uid() = user_id);

-- Create policies for resources
CREATE POLICY "Users can view all resources" ON public.resources
    FOR SELECT USING (true);

CREATE POLICY "Users can insert resources" ON public.resources
    FOR INSERT WITH CHECK (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    );

CREATE POLICY "Users can update resources" ON public.resources
    FOR UPDATE USING (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    );

CREATE POLICY "Users can delete resources" ON public.resources
    FOR DELETE USING (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    ); 